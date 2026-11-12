#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <thread>

#include "data_server.hpp"
#include "downloader.hpp"
#include "store.hpp"
#include "tracker.hpp"
#include "tracker_client.hpp"

using namespace sp;

namespace {

volatile sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

void install_signals() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
}

[[noreturn]] void usage(int code) {
    std::fputs(
        "uso: streamp2p COMANDO [opcoes]\n"
        "\n"
        "  tracker  servidor de controle (registro, catalogo, descoberta e painel web)\n"
        "    -p PORTA   porta TCP de controle (padrao 7000)\n"
        "    -w PORTA   porta HTTP do painel web (padrao 8080; 0 desliga)\n"
        "    -t MS      tempo sem heartbeat para dar o peer como caido (padrao 6000)\n"
        "    -k CHAVE   chave compartilhada (ou variavel STREAMP2P_KEY)\n"
        "    -v         log detalhado\n"
        "\n"
        "  seed     peer que publica um arquivo e atende pedidos de chunks\n"
        "    -t HOST:PORTA  tracker      -f ARQUIVO  arquivo a publicar      -n NOME  nome do conteudo\n"
        "    -c BYTES   tamanho do chunk (padrao 16384)     -b KBPS  taxa de reproducao (padrao 2000)\n"
        "    -d DIR     armazenamento local     -i ID  identificador do peer     -p PORTA  TCP de dados   -u PORTA  UDP de dados\n"
        "    -R MS      temporizador de retransmissao UDP (padrao 100)\n"
        "    -r KBPS    limite de upload        -l P  perda (0 a 1)   -D MS  atraso   -j MS  jitter   -C P  corrupcao de chunks\n"
        "    -S SEMENTE do emulador             -L SEG  encerra apos SEG segundos      -k CHAVE   -v\n"
        "\n"
        "  get      peer que baixa e reproduz um conteudo (e o repassa a outros peers)\n"
        "    -t HOST:PORTA  tracker      -n NOME ou -I ID_HEX  conteudo      -m tcp|udp  transporte (padrao tcp)\n"
        "    -B N       chunks de pre-buffer (padrao 3)     -W N  buffer maximo a frente da reproducao, em chunks (padrao 64)\n"
        "    -w N       threads de busca (padrao 4)   -P N  requisicoes simultaneas por peer (padrao 2)\n"
        "    -O ORDEM   escolha do proximo chunk na janela: strict (em ordem), rarest (mais raro) ou cheap (mais copias, padrao)\n"
        "    -N         sem ritmo de reproducao (mede so a vazao)           -o ARQUIVO  grava o conteudo baixado\n"
        "    -s ARQUIVO entrega o conteudo em ordem, no ritmo da reproducao (use - para a saida padrao, p. ex. | ffplay -)\n"
        "    -X         nao anuncia os chunks que ja tem (modo cliente-servidor puro, para comparacao)\n"
        "    -T SEG     tempo maximo (padrao 120)   -R MS  temporizador UDP (padrao 100)   -l P  perda dos datagramas enviados\n"
        "    -L SEG     continua repassando por SEG segundos apos terminar   -d DIR  -i ID  -p PORTA  -u PORTA  -r KBPS  -k CHAVE  -v\n"
        "\n"
        "  list     mostra os conteudos disponiveis no tracker\n"
        "    -t HOST:PORTA  tracker      -k CHAVE\n"
        "\n"
        "  gen      gera um arquivo de teste determinista\n"
        "    -o ARQUIVO  -s BYTES  -S SEMENTE\n",
        code == 0 ? stdout : stderr);
    std::exit(code);
}

unsigned long parse_uint(const char* s, const char* what, unsigned long lo, unsigned long hi) {
    char* end = nullptr;
    errno = 0;
    unsigned long v = std::strtoul(s, &end, 10);
    if (*s < '0' || *s > '9' || *end != '\0' || errno != 0 || v < lo || v > hi) {
        std::fprintf(stderr, "erro: valor invalido para %s: '%s' (esperado de %lu a %lu)\n", what, s, lo, hi);
        std::exit(1);
    }
    return v;
}

double parse_prob(const char* s, const char* what) {
    char* end = nullptr;
    double v = std::strtod(s, &end);
    if (*s == '\0' || *end != '\0' || !(v >= 0.0 && v <= 1.0)) {
        std::fprintf(stderr, "erro: valor invalido para %s: '%s' (esperado de 0 a 1)\n", what, s);
        std::exit(1);
    }
    return v;
}

Bytes load_key(const char* opt) {
    const char* k = opt ? opt : std::getenv("STREAMP2P_KEY");
    if (!k || !*k) {
        std::fputs("erro: informe a chave compartilhada com -k ou na variavel STREAMP2P_KEY\n", stderr);
        std::exit(1);
    }
    return Bytes(reinterpret_cast<const uint8_t*>(k), reinterpret_cast<const uint8_t*>(k) + std::strlen(k));
}

Endpoint parse_tracker(const char* s) {
    Endpoint ep;
    if (!parse_endpoint(s, ep)) {
        std::fprintf(stderr, "erro: tracker invalido: '%s' (esperado HOST:PORTA)\n", s);
        std::exit(1);
    }
    return ep;
}

void sleep_until_stop(unsigned long seconds) {
    uint64_t end = seconds ? now_ms() + seconds * 1000 : 0;
    while (!g_stop && (end == 0 || now_ms() < end)) std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

struct PeerOpts {
    const char* key = nullptr;
    Endpoint tracker;
    bool have_tracker = false;
    std::string dir, id;
    uint16_t tcp_port = 0, udp_port = 0;
    LinkProfile profile;
};

void finish_options(PeerOpts& po) {
    if (!po.have_tracker) {
        std::fputs("erro: informe o tracker com -t HOST:PORTA\n", stderr);
        std::exit(1);
    }
    if (po.id.empty()) po.id = "peer-" + to_hex(random_bytes(3).data(), 3);
    if (!valid_id(po.id)) {
        std::fputs("erro: identificador invalido (use de 1 a 32 caracteres entre letras, digitos, ponto, hifen e sublinhado)\n", stderr);
        std::exit(1);
    }
    if (po.dir.empty()) po.dir = "store-" + po.id;
}

int cmd_tracker(int argc, char** argv) {
    Tracker::Config cfg;
    cfg.web_port = 8080;
    const char* key = nullptr;
    int c;
    while ((c = getopt(argc, argv, "p:w:t:k:vh")) != -1) {
        switch (c) {
            case 'p': cfg.port = static_cast<uint16_t>(parse_uint(optarg, "-p", 1, 65535)); break;
            case 'w': {
                unsigned long w = parse_uint(optarg, "-w", 0, 65535);
                cfg.web_port = w == 0 ? -1 : static_cast<int>(w);
                break;
            }
            case 't': cfg.ttl_ms = parse_uint(optarg, "-t", 300, 600000); break;
            case 'k': key = optarg; break;
            case 'v': set_log_level(LogLevel::Debug); break;
            case 'h': usage(0);
            default: usage(1);
        }
    }
    cfg.psk = load_key(key);
    install_signals();
    Tracker tracker(cfg);
    try {
        tracker.start();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "erro: %s\n", e.what());
        return 1;
    }
    std::printf("tracker pronto: tcp=%u web=%u\n", tracker.port(), tracker.web_port());
    std::fflush(stdout);
    sleep_until_stop(0);
    tracker.stop();
    TrackerStats s = tracker.state().stats();
    std::printf("STATS {\"registrations\":%llu,\"expired\":%llu,\"auth_failures\":%llu,\"heartbeats\":%llu,\"lookups\":%llu}\n",
                static_cast<unsigned long long>(s.registrations), static_cast<unsigned long long>(s.expired),
                static_cast<unsigned long long>(s.auth_failures), static_cast<unsigned long long>(s.heartbeats),
                static_cast<unsigned long long>(s.lookups));
    return 0;
}

int cmd_seed(int argc, char** argv) {
    PeerOpts po;
    std::string file, name;
    uint32_t udp_rto = 100;
    unsigned long chunk = 16384, bitrate = 2000, run_for = 0;
    int c;
    while ((c = getopt(argc, argv, "t:k:f:n:c:b:d:i:p:u:r:R:l:D:j:C:S:L:vh")) != -1) {
        switch (c) {
            case 't': po.tracker = parse_tracker(optarg); po.have_tracker = true; break;
            case 'k': po.key = optarg; break;
            case 'f': file = optarg; break;
            case 'n': name = optarg; break;
            case 'c': chunk = parse_uint(optarg, "-c", kMinChunkSize, kMaxChunkSize); break;
            case 'b': bitrate = parse_uint(optarg, "-b", 0, 1000000); break;
            case 'd': po.dir = optarg; break;
            case 'i': po.id = optarg; break;
            case 'p': po.tcp_port = static_cast<uint16_t>(parse_uint(optarg, "-p", 0, 65535)); break;
            case 'u': po.udp_port = static_cast<uint16_t>(parse_uint(optarg, "-u", 0, 65535)); break;
            case 'r': po.profile.rate_bps = parse_uint(optarg, "-r", 0, 100000000) * 1000; break;
            case 'R': udp_rto = static_cast<uint32_t>(parse_uint(optarg, "-R", 10, 10000)); break;
            case 'l': po.profile.loss = parse_prob(optarg, "-l"); break;
            case 'D': po.profile.delay_ms = static_cast<uint32_t>(parse_uint(optarg, "-D", 0, 60000)); break;
            case 'j': po.profile.jitter_ms = static_cast<uint32_t>(parse_uint(optarg, "-j", 0, 60000)); break;
            case 'C': po.profile.corrupt = parse_prob(optarg, "-C"); break;
            case 'S': po.profile.seed = parse_uint(optarg, "-S", 0, ~0ul); break;
            case 'L': run_for = parse_uint(optarg, "-L", 1, 86400); break;
            case 'v': set_log_level(LogLevel::Debug); break;
            case 'h': usage(0);
            default: usage(1);
        }
    }
    finish_options(po);
    Bytes psk = load_key(po.key);
    install_signals();
    if (!file.empty() && !std::ifstream(file, std::ios::binary)) {
        std::fprintf(stderr, "erro: arquivo ausente ou ilegivel: %s\n", file.c_str());
        return 1;
    }
    ChunkStore store(po.dir);
    store.load();
    if (!file.empty()) {
        if (name.empty()) {
            size_t slash = file.rfind('/');
            name = slash == std::string::npos ? file : file.substr(slash + 1);
        }
        try {
            store.import_file(file, name, static_cast<uint32_t>(chunk), static_cast<uint32_t>(bitrate));
        } catch (const std::exception& e) {
            std::fprintf(stderr, "erro: %s\n", e.what());
            return 1;
        }
    }
    DataServer::Config dc;
    dc.id = po.id;
    dc.psk = psk;
    dc.profile = po.profile;
    dc.tcp_port = po.tcp_port;
    dc.udp_port = po.udp_port;
    dc.udp_rto_ms = udp_rto;
    DataServer server(store, dc);
    try {
        server.start();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "erro: %s\n", e.what());
        return 1;
    }
    std::atomic<uint64_t> downloaded{0};
    TrackerClient::Config tc;
    tc.tracker = po.tracker;
    tc.psk = psk;
    tc.id = po.id;
    tc.tcp_port = server.tcp_port();
    tc.udp_port = server.udp_port();
    TrackerClient client(tc, store, [&](uint64_t& up, uint64_t& down) {
        up = server.stats.uploaded_bytes.load();
        down = downloaded.load();
    });
    client.start();
    if (!client.wait_connected(5000)) std::fprintf(stderr, "aviso: ainda sem conexao com o tracker (tentando em segundo plano)\n");
    std::printf("seed pronto: id=%s tcp=%u udp=%u\n", po.id.c_str(), server.tcp_port(), server.udp_port());
    for (const Digest& id : store.contents()) {
        Manifest m;
        store.manifest(id, m);
        std::printf("conteudo %s %s chunks=%zu\n", to_hex(id).c_str(), m.name.c_str(), m.chunks());
    }
    std::fflush(stdout);
    sleep_until_stop(run_for);
    client.stop();
    server.stop();
    std::printf("STATS %s\n", server.stats_json().c_str());
    return 0;
}

int cmd_get(int argc, char** argv) {
    PeerOpts po;
    GetOptions opt;
    std::string name, id_hex, stream_path;
    std::FILE* text_out = stdout;
    bool share = true;
    unsigned long linger = 0;
    int c;
    while ((c = getopt(argc, argv, "t:k:n:I:m:B:W:w:NXO:P:o:s:T:R:l:L:d:i:p:u:r:vh")) != -1) {
        switch (c) {
            case 't': po.tracker = parse_tracker(optarg); po.have_tracker = true; break;
            case 'k': po.key = optarg; break;
            case 'n': name = optarg; break;
            case 'I': id_hex = optarg; break;
            case 'm':
                if (std::strcmp(optarg, "tcp") == 0) opt.transport = Transport::Tcp;
                else if (std::strcmp(optarg, "udp") == 0) opt.transport = Transport::Udp;
                else {
                    std::fprintf(stderr, "erro: transporte invalido: '%s' (use tcp ou udp)\n", optarg);
                    return 1;
                }
                break;
            case 'B': opt.prebuffer = static_cast<int>(parse_uint(optarg, "-B", 1, 100000)); break;
            case 'W': opt.window = static_cast<int>(parse_uint(optarg, "-W", 1, 100000)); break;
            case 'w': opt.workers = static_cast<int>(parse_uint(optarg, "-w", 1, 64)); break;
            case 'N': opt.pace = false; break;
            case 'X': share = false; break;
            case 'O':
                if (std::strcmp(optarg, "strict") == 0) opt.order = Order::Strict;
                else if (std::strcmp(optarg, "rarest") == 0) opt.order = Order::Rarest;
                else if (std::strcmp(optarg, "cheap") == 0) opt.order = Order::Cheap;
                else {
                    std::fprintf(stderr, "erro: ordem invalida: '%s' (use strict, rarest ou cheap)\n", optarg);
                    return 1;
                }
                break;
            case 'P': opt.max_inflight_per_peer = static_cast<int>(parse_uint(optarg, "-P", 1, 64)); break;
            case 'o': opt.out_path = optarg; break;
            case 's': stream_path = optarg; break;
            case 'T': opt.total_timeout_ms = static_cast<uint32_t>(parse_uint(optarg, "-T", 1, 86400) * 1000); break;
            case 'R': opt.rto_ms = static_cast<uint32_t>(parse_uint(optarg, "-R", 10, 10000)); break;
            case 'l': opt.client_profile.loss = parse_prob(optarg, "-l"); break;
            case 'L': linger = parse_uint(optarg, "-L", 1, 86400); break;
            case 'd': po.dir = optarg; break;
            case 'i': po.id = optarg; break;
            case 'p': po.tcp_port = static_cast<uint16_t>(parse_uint(optarg, "-p", 0, 65535)); break;
            case 'u': po.udp_port = static_cast<uint16_t>(parse_uint(optarg, "-u", 0, 65535)); break;
            case 'r': po.profile.rate_bps = parse_uint(optarg, "-r", 0, 100000000) * 1000; break;
            case 'v': set_log_level(LogLevel::Debug); break;
            case 'h': usage(0);
            default: usage(1);
        }
    }
    finish_options(po);
    if (name.empty() == id_hex.empty()) {
        std::fputs("erro: informe o conteudo com -n NOME ou -I ID_HEX (apenas um)\n", stderr);
        return 1;
    }
    Digest cid{};
    if (!id_hex.empty() && !from_hex(id_hex, cid)) {
        std::fputs("erro: identificador de conteudo invalido (esperado 64 digitos hexadecimais)\n", stderr);
        return 1;
    }
    Bytes psk = load_key(po.key);
    install_signals();
    if (stream_path == "-") {
        opt.stream_fd = STDOUT_FILENO;
        text_out = stderr;
    } else if (!stream_path.empty()) {
        opt.stream_fd = ::open(stream_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (opt.stream_fd < 0) {
            std::fprintf(stderr, "erro: nao foi possivel abrir %s para a saida de streaming\n", stream_path.c_str());
            return 1;
        }
    }
    ChunkStore store(po.dir);
    store.load();
    DataServer::Config dc;
    dc.id = po.id;
    dc.psk = psk;
    dc.profile = po.profile;
    dc.tcp_port = po.tcp_port;
    dc.udp_port = po.udp_port;
    DataServer server(store, dc);
    try {
        server.start();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "erro: %s\n", e.what());
        return 1;
    }
    std::atomic<uint64_t> downloaded{0};
    TrackerClient::Config tc;
    tc.tracker = po.tracker;
    tc.psk = psk;
    tc.id = po.id;
    tc.tcp_port = server.tcp_port();
    tc.udp_port = server.udp_port();
    tc.share = share;
    TrackerClient client(tc, store, [&](uint64_t& up, uint64_t& down) {
        up = server.stats.uploaded_bytes.load();
        down = downloaded.load();
    });
    client.start();
    if (!name.empty()) {
        uint64_t deadline = now_ms() + opt.total_timeout_ms;
        bool found = false;
        while (!g_stop && now_ms() < deadline && !found) {
            std::vector<ContentSummary> list;
            if (client.wait_connected(200) && client.list(list)) {
                for (const ContentSummary& s : list) {
                    if (s.name == name && (!found || s.seeders > 0)) {
                        cid = s.id;
                        found = true;
                    }
                }
            }
            if (!found) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!found) {
            std::fprintf(stderr, "erro: conteudo '%s' nao encontrado no tracker\n", name.c_str());
            client.stop();
            server.stop();
            return 2;
        }
    }
    Downloader dl(store, client, psk, po.id, opt);
    dl.set_downloaded_counter(&downloaded);
    GetResult res = dl.run(cid);
    if (opt.stream_fd >= 0 && opt.stream_fd != STDOUT_FILENO) ::close(opt.stream_fd);
    std::fprintf(text_out, "RESULT %s\n", res.to_json().c_str());
    std::fflush(text_out);
    if (res.ok && linger > 0) sleep_until_stop(linger);
    client.stop();
    server.stop();
    std::fprintf(text_out, "STATS %s\n", server.stats_json().c_str());
    return res.ok ? 0 : 2;
}

int cmd_list(int argc, char** argv) {
    const char* key = nullptr;
    Endpoint tracker;
    bool have_tracker = false;
    int c;
    while ((c = getopt(argc, argv, "t:k:vh")) != -1) {
        switch (c) {
            case 't': tracker = parse_tracker(optarg); have_tracker = true; break;
            case 'k': key = optarg; break;
            case 'v': set_log_level(LogLevel::Debug); break;
            case 'h': usage(0);
            default: usage(1);
        }
    }
    if (!have_tracker) {
        std::fputs("erro: informe o tracker com -t HOST:PORTA\n", stderr);
        return 1;
    }
    Bytes psk = load_key(key);
    install_signals();
    try {
        SecureChannel ch(connect_tcp(tracker, 3000));
        ch.handshake_client(psk, "list-" + to_hex(random_bytes(3).data(), 3), kRoleTracker, 3000);
        ch.send(Msg::Register, encode_register(0, 0));
        Frame f;
        if (!ch.recv(f, 3000) || f.type != static_cast<uint8_t>(Msg::RegisterOk)) throw NetError("o tracker recusou o registro");
        ch.send(Msg::List, Bytes());
        if (!ch.recv(f, 3000) || f.type != static_cast<uint8_t>(Msg::ListReply)) throw NetError("resposta inesperada do tracker");
        std::vector<ContentSummary> list = decode_list_reply(f.payload);
        ch.send(Msg::Bye, Bytes());
        std::sort(list.begin(), list.end(), [](const ContentSummary& a, const ContentSummary& b) { return a.name < b.name; });
        if (list.empty()) {
            std::puts("nenhum conteudo disponivel");
            return 0;
        }
        std::printf("%-24s %12s %7s %7s %8s %6s  %s\n", "NOME", "BYTES", "CHUNKS", "KBIT/S", "SEEDERS", "PEERS", "ID");
        for (const ContentSummary& s : list)
            std::printf("%-24s %12llu %7u %7u %8u %6u  %s\n", s.name.c_str(), static_cast<unsigned long long>(s.size), s.chunks, s.bitrate_kbps,
                        s.seeders, s.holders, to_hex(s.id).c_str());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "erro: %s\n", e.what());
        return 2;
    }
}

int cmd_gen(int argc, char** argv) {
    std::string out;
    unsigned long size = 0, seed = 1;
    int c;
    while ((c = getopt(argc, argv, "o:s:S:h")) != -1) {
        switch (c) {
            case 'o': out = optarg; break;
            case 's': size = parse_uint(optarg, "-s", 1, 4ul << 30); break;
            case 'S': seed = parse_uint(optarg, "-S", 0, ~0ul); break;
            case 'h': usage(0);
            default: usage(1);
        }
    }
    if (out.empty() || size == 0) {
        std::fputs("erro: informe -o ARQUIVO e -s BYTES\n", stderr);
        return 1;
    }
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if (!f) {
        std::fprintf(stderr, "erro: nao foi possivel criar %s\n", out.c_str());
        return 1;
    }
    Rng rng(seed);
    Bytes buf(65536);
    unsigned long left = size;
    while (left > 0) {
        size_t n = left < buf.size() ? left : buf.size();
        for (size_t i = 0; i < n; i += 8) {
            uint64_t v = rng.next();
            for (size_t k = 0; k < 8 && i + k < n; k++) buf[i + k] = static_cast<uint8_t>(v >> (8 * k));
        }
        f.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(n));
        left -= n;
    }
    return f ? 0 : 1;
}

}

int main(int argc, char** argv) {
    if (argc < 2) usage(1);
    std::string cmd = argv[1];
    if (cmd == "-h" || cmd == "--help") usage(0);
    argv[1] = argv[0];
    int sub_argc = argc - 1;
    char** sub_argv = argv + 1;
    optind = 1;
    if (cmd == "tracker") return cmd_tracker(sub_argc, sub_argv);
    if (cmd == "seed") return cmd_seed(sub_argc, sub_argv);
    if (cmd == "get") return cmd_get(sub_argc, sub_argv);
    if (cmd == "list") return cmd_list(sub_argc, sub_argv);
    if (cmd == "gen") return cmd_gen(sub_argc, sub_argv);
    std::fprintf(stderr, "erro: comando desconhecido '%s'\n", cmd.c_str());
    usage(1);
}
