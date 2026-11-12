#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <thread>

#include "data_server.hpp"
#include "emulation.hpp"
#include "http.hpp"
#include "manifest.hpp"
#include "protocol.hpp"
#include "sha256.hpp"
#include "store.hpp"
#include "tracker.hpp"
#include "util.hpp"

using namespace sp;
namespace fs = std::filesystem;

namespace {

int g_pass = 0, g_fail = 0;

void section(const char* name) { std::printf("\n=== %s ===\n", name); }

void check(bool ok, const std::string& what) {
    if (ok) {
        g_pass++;
        std::printf("  ok   %s\n", what.c_str());
    } else {
        g_fail++;
        std::printf("  FALHOU %s\n", what.c_str());
    }
}

Bytes B(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::string make_tmp_dir() {
    char tmpl[] = "/tmp/streamp2p-test-XXXXXX";
    char* d = mkdtemp(tmpl);
    return d ? std::string(d) : std::string("/tmp/streamp2p-test-fallback");
}

template <typename F>
bool throws_decode_only(F fn) {
    try {
        fn();
    } catch (const DecodeError&) {
    } catch (...) {
        return false;
    }
    return true;
}

Digest sha_of(const std::string& s) { return sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

struct Relay {
    int client_end = -1, relay_a = -1, server_end = -1, relay_b = -1;
    std::atomic<int> mode{0};
    std::atomic<bool> stop{false};
    std::thread thread;
    Relay() {
        int p[2], q[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, p);
        socketpair(AF_UNIX, SOCK_STREAM, 0, q);
        client_end = p[0];
        relay_a = p[1];
        server_end = q[0];
        relay_b = q[1];
        thread = std::thread([this] { run(); });
    }
    ~Relay() {
        stop = true;
        if (thread.joinable()) thread.join();
        ::close(relay_a);
        ::close(relay_b);
    }
    void run() {
        uint8_t buf[8192];
        while (!stop) {
            pollfd fds[2] = {{relay_a, POLLIN, 0}, {relay_b, POLLIN, 0}};
            if (::poll(fds, 2, 20) <= 0) continue;
            if (fds[0].revents & POLLIN) {
                ssize_t n = ::read(relay_a, buf, sizeof buf);
                if (n <= 0) break;
                int m = mode.exchange(0);
                if (m == 1) buf[n - 1] ^= 0x01;
                (void)!::write(relay_b, buf, static_cast<size_t>(n));
                if (m == 2) (void)!::write(relay_b, buf, static_cast<size_t>(n));
            }
            if (fds[1].revents & POLLIN) {
                ssize_t n = ::read(relay_b, buf, sizeof buf);
                if (n <= 0) break;
                (void)!::write(relay_a, buf, static_cast<size_t>(n));
            }
        }
    }
};

}

static void test_sha256_hmac() {
    section("SHA-256 e HMAC-SHA256 contra vetores de referencia");
    check(to_hex(sha256(Bytes{})) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256 da mensagem vazia");
    check(to_hex(sha_of("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 de 'abc'");
    check(to_hex(sha_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "SHA-256 da mensagem de 448 bits do NIST");
    Sha256 big;
    Bytes block(1000, 'a');
    for (int i = 0; i < 1000; i++) big.update(block);
    check(to_hex(big.finish()) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "SHA-256 de um milhao de 'a' em atualizacoes incrementais");
    Rng rng(5);
    Bytes data(100000);
    for (auto& b : data) b = static_cast<uint8_t>(rng.next());
    Digest whole = sha256(data);
    bool same = true;
    for (int t = 0; t < 20; t++) {
        Sha256 s;
        size_t pos = 0;
        while (pos < data.size()) {
            size_t n = std::min<size_t>(1 + rng.below(300), data.size() - pos);
            s.update(data.data() + pos, n);
            pos += n;
        }
        same = same && s.finish() == whole;
    }
    check(same, "SHA-256 incremental com cortes aleatorios igual ao calculo de uma vez");
    check(to_hex(hmac_sha256(Bytes{11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11}, Bytes{72,105,32,84,104,101,114,101})) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "HMAC-SHA256 RFC 4231, caso 1");
    check(to_hex(hmac_sha256(Bytes{74,101,102,101}, Bytes{119,104,97,116,32,100,111,32,121,97,32,119,97,110,116,32,102,111,114,32,110,111,116,104,105,110,103,63})) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "HMAC-SHA256 RFC 4231, caso 2");
    check(to_hex(hmac_sha256(Bytes{170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170}, Bytes{221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221,221})) == "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", "HMAC-SHA256 RFC 4231, caso 3");
    check(to_hex(hmac_sha256(Bytes{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25}, Bytes{205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205,205})) == "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", "HMAC-SHA256 RFC 4231, caso 4");
    check(to_hex(hmac_sha256(Bytes{170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170}, Bytes{84,101,115,116,32,85,115,105,110,103,32,76,97,114,103,101,114,32,84,104,97,110,32,66,108,111,99,107,45,83,105,122,101,32,75,101,121,32,45,32,72,97,115,104,32,75,101,121,32,70,105,114,115,116})) == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "HMAC-SHA256 RFC 4231, caso 6");
    check(to_hex(hmac_sha256(Bytes{170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170}, Bytes{84,104,105,115,32,105,115,32,97,32,116,101,115,116,32,117,115,105,110,103,32,97,32,108,97,114,103,101,114,32,116,104,97,110,32,98,108,111,99,107,45,115,105,122,101,32,107,101,121,32,97,110,100,32,97,32,108,97,114,103,101,114,32,116,104,97,110,32,98,108,111,99,107,45,115,105,122,101,32,100,97,116,97,46,32,84,104,101,32,107,101,121,32,110,101,101,100,115,32,116,111,32,98,101,32,104,97,115,104,101,100,32,98,101,102,111,114,101,32,98,101,105,110,103,32,117,115,101,100,32,98,121,32,116,104,101,32,72,77,65,67,32,97,108,103,111,114,105,116,104,109,46})) == "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", "HMAC-SHA256 RFC 4231, caso 7");
    check(ct_equal(whole.data(), whole.data(), 32) && !ct_equal(whole.data(), sha_of("x").data(), 32), "comparacao em tempo constante");
}

static void test_codec() {
    section("codec binario, limites e robustez dos decodificadores");
    ByteWriter w;
    w.u8(7);
    w.u16(0xABCD);
    w.u32(0xDEADBEEF);
    w.u64(0x0123456789ABCDEFull);
    w.str("ola");
    w.blob(Bytes{1, 2, 3});
    ByteReader r(w.bytes());
    check(r.u8() == 7 && r.u16() == 0xABCD && r.u32() == 0xDEADBEEF && r.u64() == 0x0123456789ABCDEFull && r.str() == "ola" && r.blob(10) == Bytes({1, 2, 3}), "ida e volta de inteiros, texto e blob");
    r.expect_end();
    check(throws_decode_only([] { Bytes b{1}; ByteReader r2(b); r2.u32(); }), "leitura alem do fim lanca DecodeError");
    check(throws_decode_only([] { ByteWriter x; x.u32(1000); ByteReader r3(x.bytes()); r3.blob(10); }), "blob acima do limite lanca DecodeError");
    Rng rng(11);
    bool only_decode = true;
    Manifest m;
    m.name = "video";
    m.size = 5000;
    m.chunk_size = 2048;
    for (int i = 0; i < 3; i++) m.hashes.push_back(sha_of("c" + std::to_string(i)));
    LookupReply lr;
    lr.manifest = m;
    Bitmap bm(3);
    bm.set(0);
    bm.set(2);
    lr.peers.push_back(PeerInfo{"peer1", "127.0.0.1", 1000, 2000, bm});
    HeartbeatMsg hb;
    hb.holds.push_back(Holding{m.id(), bm.bytes()});
    std::vector<Bytes> seeds = {encode_lookup_reply(lr), encode_heartbeat(hb), encode_list_reply({ContentSummary{m.id(), "video", 5000, 2048, 2000, 3, 1, 2}}),
                                encode_chunk_data(1, Bytes(100, 9)), encode_chunk_req(m.id(), 2), encode_register(1, 2), encode_digests({m.id()}), m.encode()};
    for (int i = 0; i < 60000; i++) {
        Bytes input;
        if (i % 2 == 0) {
            input.resize(rng.below(300));
            for (auto& b : input) b = static_cast<uint8_t>(rng.next());
        } else {
            input = seeds[rng.below(static_cast<uint32_t>(seeds.size()))];
            for (uint32_t k = 0, n = 1 + rng.below(4); k < n && !input.empty(); k++) input[rng.below(static_cast<uint32_t>(input.size()))] = static_cast<uint8_t>(rng.next());
            if (rng.below(4) == 0 && !input.empty()) input.resize(rng.below(static_cast<uint32_t>(input.size())));
        }
        only_decode = only_decode && throws_decode_only([&] { decode_lookup_reply(input); }) && throws_decode_only([&] { decode_heartbeat(input); }) &&
                      throws_decode_only([&] { decode_list_reply(input); }) && throws_decode_only([&] { uint32_t i2; Bytes d; decode_chunk_data(input, i2, d); }) &&
                      throws_decode_only([&] { Digest c; uint32_t i2; decode_chunk_req(input, c, i2); }) && throws_decode_only([&] { uint16_t a, b; decode_register(input, a, b); }) &&
                      throws_decode_only([&] { decode_digests(input); }) && throws_decode_only([&] { ByteReader rr(input); Manifest::decode(rr); });
    }
    check(only_decode, "60 mil entradas aleatorias ou mutadas em 8 decodificadores: so ocorre DecodeError, sem falha de memoria");
    LookupReply back = decode_lookup_reply(encode_lookup_reply(lr));
    check(back.manifest.id() == m.id() && back.peers.size() == 1 && back.peers[0].have.get(2) && !back.peers[0].have.get(1), "mensagem de consulta: ida e volta preserva manifesto e bitmap");
}

static void test_manifest_store() {
    section("manifesto, bitmap e armazenamento de chunks");
    std::string dir = make_tmp_dir();
    std::string file = dir + "/src.bin";
    Rng rng(3);
    Bytes content(40000);
    for (auto& b : content) b = static_cast<uint8_t>(rng.next());
    {
        std::ofstream f(file, std::ios::binary);
        f.write(reinterpret_cast<const char*>(content.data()), static_cast<std::streamsize>(content.size()));
    }
    ChunkStore store(dir + "/store");
    Manifest m = store.import_file(file, "amostra", 16384, 1000);
    check(m.valid() && m.chunks() == 3 && m.chunk_len(0) == 16384 && m.chunk_len(2) == 40000 - 2 * 16384 && m.chunk_len(3) == 0, "importar arquivo gera 3 chunks com os tamanhos certos");
    check(m.chunk_duration_ms(0) > 130 && m.chunk_duration_ms(0) < 132, "duracao de um chunk de 16 KiB a 1000 kbit/s e cerca de 131 ms");
    Digest id = m.id();
    Manifest tampered = m;
    tampered.hashes[1][0] ^= 1;
    check(tampered.id() != id, "alterar o hash de um chunk muda o identificador do conteudo");
    check(store.bitmap(id).full(), "o conteudo importado fica completo no armazenamento");
    Bytes chunk;
    check(store.get(id, 1, chunk) && chunk == Bytes(content.begin() + 16384, content.begin() + 32768), "chunk lido do disco igual ao do arquivo");
    ChunkStore other(dir + "/other");
    check(other.add_manifest(m) && !other.add_manifest(m), "adicionar um manifesto novo funciona uma vez");
    Bytes bad = chunk;
    bad[10] ^= 0xFF;
    check(!other.put(id, 1, bad), "chunk com conteudo adulterado e rejeitado pelo hash");
    check(!other.put(id, 1, Bytes(10, 1)), "chunk com tamanho errado e rejeitado");
    check(other.put(id, 1, chunk) && other.bitmap(id).get(1) && other.bitmap(id).count() == 1, "chunk correto e aceito e marcado no bitmap");
    for (uint32_t i : {0u, 2u}) {
        Bytes c;
        store.get(id, i, c);
        other.put(id, i, c);
    }
    std::string out = dir + "/out.bin";
    check(other.assemble(id, out), "conteudo completo pode ser remontado");
    std::ifstream f(out, std::ios::binary);
    Bytes got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    check(got == content, "arquivo remontado identico ao original");
    {
        std::ofstream corrupt(dir + "/other/" + to_hex(id) + "/0.chunk", std::ios::binary | std::ios::trunc);
        corrupt << "lixo";
    }
    ChunkStore reloaded(dir + "/other");
    reloaded.load();
    Bitmap bmr = reloaded.bitmap(id);
    check(!bmr.get(0) && bmr.get(1) && bmr.get(2), "ao recarregar, o chunk corrompido em disco e descartado e os demais sao mantidos");
    Bitmap parsed;
    check(Bitmap::from_bytes(Bytes{0xFF}, 5, parsed) && parsed.count() == 5 && !Bitmap::from_bytes(Bytes{0xFF, 0}, 5, parsed), "bitmap ignora bits alem do tamanho e rejeita comprimento errado");
    Manifest inv = m;
    inv.chunk_size = 10;
    check(!inv.valid(), "manifesto com chunk_size fora dos limites e invalido");
    Manifest huge;
    huge.name = "x";
    huge.size = ~0ull;
    huge.chunk_size = 1024;
    check(!huge.valid(), "manifesto com tamanho gigante e sem hashes e invalido (sem estouro de inteiro)");
    ByteWriter crafted;
    crafted.str("x");
    crafted.u64(~0ull);
    crafted.u32(1024);
    crafted.u32(0);
    crafted.u32(0);
    bool refused = false;
    try {
        ByteReader cr(crafted.bytes());
        Manifest::decode(cr);
    } catch (const DecodeError&) {
        refused = true;
    }
    check(refused, "decodificar esse manifesto forjado lanca DecodeError");
    Manifest limit = m;
    limit.size = static_cast<uint64_t>(limit.chunk_size) * kMaxChunks + 1;
    check(!limit.valid(), "manifesto acima de 2^20 chunks e invalido");
    fs::remove_all(dir);
}

static void test_channel() {
    section("canal autenticado: handshake, adulteracao e repeticao");
    Bytes key = B("chave-de-teste");
    {
        Relay relay;
        SecureChannel client{Fd(relay.client_end)};
        SecureChannel server{Fd(relay.server_end)};
        std::string id;
        uint8_t role = 99;
        std::thread t([&] { server.handshake_server(key, 2000, id, role); });
        client.handshake_client(key, "peer-a", kRoleData, 2000);
        t.join();
        check(id == "peer-a" && role == kRoleData, "handshake mutuo com a chave certa identifica o peer e o papel");
        client.send(Msg::Heartbeat, B("ola"));
        Frame f;
        check(server.recv(f, 1000) && f.type == static_cast<uint8_t>(Msg::Heartbeat) && f.payload == B("ola"), "mensagem do cliente chega integra ao servidor");
        server.send(Msg::HeartbeatOk, B("resposta"));
        check(client.recv(f, 1000) && f.payload == B("resposta"), "mensagem do servidor chega integra ao cliente");
        check(!server.recv(f, 50), "sem trafego, recv expira sem erro");
        relay.mode = 1;
        client.send(Msg::Heartbeat, B("adulterada"));
        bool tamper = false;
        try {
            server.recv(f, 1000);
        } catch (const AuthError&) {
            tamper = true;
        }
        check(tamper, "um bit alterado no MAC e detectado (AuthError)");
    }
    {
        Relay relay;
        SecureChannel client{Fd(relay.client_end)};
        SecureChannel server{Fd(relay.server_end)};
        std::string id;
        uint8_t role;
        std::thread t([&] { server.handshake_server(key, 2000, id, role); });
        client.handshake_client(key, "peer-b", kRoleTracker, 2000);
        t.join();
        relay.mode = 2;
        client.send(Msg::Heartbeat, B("uma vez so"));
        Frame f;
        bool first = server.recv(f, 1000) && f.payload == B("uma vez so");
        bool replay = false;
        try {
            server.recv(f, 1000);
        } catch (const AuthError&) {
            replay = true;
        }
        check(first && replay, "mensagem repetida por um atacante e rejeitada (contador implicito)");
    }
    {
        Relay relay;
        SecureChannel client{Fd(relay.client_end)};
        SecureChannel server{Fd(relay.server_end)};
        std::string id;
        uint8_t role;
        bool server_failed = false;
        std::thread t([&] {
            try {
                server.handshake_server(B("outra-chave"), 2000, id, role);
            } catch (const AuthError&) {
                server_failed = true;
            } catch (const std::exception&) {
            }
        });
        bool client_failed = false;
        try {
            client.handshake_client(key, "peer-c", kRoleData, 2000);
        } catch (const AuthError&) {
            client_failed = true;
        } catch (const NetError&) {
            client_failed = true;
        }
        t.join();
        check(client_failed && server_failed, "chaves diferentes: os dois lados recusam o handshake e o servidor o contabiliza como falha de autenticacao");
    }
    {
        Relay relay;
        SecureChannel client{Fd(relay.client_end)};
        SecureChannel server{Fd(relay.server_end)};
        std::string id;
        uint8_t role;
        std::thread t([&] { server.handshake_server(key, 2000, id, role); });
        client.handshake_client(key, "peer-d", kRoleData, 2000);
        t.join();
        check(throws_decode_only([&] {
                  try {
                      client.send(Msg::ChunkData, Bytes(kMaxFramePayload + 1));
                  } catch (const NetError&) {
                  }
              }),
              "mensagem acima do limite de quadro nao e enviada");
    }
    check(valid_id("peer-1.a_b") && !valid_id("") && !valid_id("<script>") && !valid_id("a b") && !valid_id(std::string(33, 'a')), "identificadores de peer: apenas caracteres seguros e ate 32");
    check(valid_name("Filme Ação 2026") && !valid_name("") && !valid_name("tab\there") && !valid_name(std::string("\xff\xfe")) && !valid_name(std::string(65, 'a')), "nomes de conteudo: UTF-8 valido, sem controles, ate 64 bytes");
    check(valid_name("\xc2\xa0\xe0\xa0\x80\xed\x9f\xbf\xf0\x90\x80\x80\xf4\x8f\xbf\xbf") && !valid_name("a\xc2\x85" "b") && !valid_name("\xc0\xaf") && !valid_name("\xe0\x80\xaf") &&
              !valid_name("\xed\xa0\x80") && !valid_name("\xf0\x80\x80\xaf") && !valid_name("\xf4\x90\x80\x80") && !valid_name("\xe2\x82"),
          "nomes de conteudo: UTF-8 estrito (recusa controles C1, codificacao longa demais, surrogates, acima de U+10FFFF e sequencia cortada)");
    {
        int sv[2];
        ::socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        Fd attacker(sv[0]);
        SecureChannel server{Fd(sv[1])};
        const uint8_t half[] = {'S', 'P', kVersion, 1};
        send_all(attacker.get(), half, sizeof half, 100);
        std::string id;
        uint8_t role;
        uint64_t t0 = now_ms();
        bool failed = false;
        try {
            server.handshake_server(key, 300, id, role);
        } catch (const std::exception&) {
            failed = true;
        }
        uint64_t dt = now_ms() - t0;
        check(failed && dt >= 250 && dt < 1500, "handshake: quem envia meio cabecalho e para e desligado no prazo da etapa (300 ms), nao no prazo do corpo dos quadros");
    }
    {
        int sv[2];
        ::socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        Fd attacker(sv[0]);
        SecureChannel server{Fd(sv[1])};
        const uint8_t big[] = {'S', 'P', kVersion, 1, 0, 0x40, 0, 0};
        send_all(attacker.get(), big, sizeof big, 100);
        std::string id;
        uint8_t role;
        uint64_t t0 = now_ms();
        bool refused = false;
        try {
            server.handshake_server(key, 3000, id, role);
        } catch (const AuthError&) {
            refused = true;
        } catch (const std::exception&) {
        }
        check(refused && now_ms() - t0 < 1000, "handshake: HELLO que anuncia payload acima de 256 bytes e recusado na hora, sem esperar nem reservar o corpo");
    }
}

static void test_udp_codec() {
    section("datagramas UDP autenticados");
    Bytes key = udp_key(B("chave"));
    Bytes dg = udp_seal(key, UMsg::Data, 0x1122334455667788ull, B("corpo"));
    UMsg type;
    uint64_t rid;
    Bytes body;
    check(udp_open(key, dg.data(), dg.size(), type, rid, body) && type == UMsg::Data && rid == 0x1122334455667788ull && body == B("corpo"), "selar e abrir um datagrama preserva tipo, identificador e corpo");
    Bytes flipped = dg;
    flipped[14] ^= 1;
    check(!udp_open(key, flipped.data(), flipped.size(), type, rid, body), "datagrama adulterado e descartado");
    check(!udp_open(udp_key(B("outra")), dg.data(), dg.size(), type, rid, body), "datagrama de outra chave e descartado");
    check(!udp_open(key, dg.data(), 10, type, rid, body) && !udp_open(key, dg.data(), 0, type, rid, body), "datagrama truncado e descartado");
    Rng rng(2);
    bool safe = true;
    for (int i = 0; i < 20000; i++) {
        Bytes junk(rng.below(1600));
        for (auto& b : junk) b = static_cast<uint8_t>(rng.next());
        safe = safe && !udp_open(key, junk.data(), junk.size(), type, rid, body);
    }
    check(safe, "20 mil datagramas aleatorios sao todos recusados pelo MAC");
}

static void test_emulation() {
    section("emulador de enlace: banda, atraso e ordem");
    Pacer pacer(80000);
    uint64_t a = pacer.reserve(1000, 1000), b = pacer.reserve(1000, 1000), c = pacer.reserve(1000, 5000);
    check(a == 1100 && b == 1200 && c == 5100, "a 80 kbit/s, 1000 bytes ocupam 100 ms e as reservas se enfileiram");
    check(Pacer(0).reserve(1000, 777) == 777, "sem limite de banda nao ha espera");
    std::mutex mu;
    std::vector<int> order;
    std::map<int, uint64_t> due_by_id, fired_by_id;
    {
        DelayLine line;
        uint64_t base = now_ms();
        int ids[] = {3, 1, 4, 2, 5};
        uint64_t offs[] = {90, 30, 150, 60, 150};
        for (int i = 0; i < 5; i++) {
            due_by_id[ids[i]] = base + offs[i];
            line.schedule(base + offs[i], [&, id = ids[i]] {
                std::lock_guard<std::mutex> lock(mu);
                order.push_back(id);
                fired_by_id[id] = now_ms();
            });
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    check(order == std::vector<int>({1, 2, 3, 4, 5}), "a fila de atraso executa por instante de vencimento e, em empate, na ordem de insercao");
    bool not_early = fired_by_id.size() == 5;
    for (const auto& kv : fired_by_id) not_early = not_early && kv.second + 1 >= due_by_id[kv.first];
    check(not_early, "nenhum item dispara antes do vencimento e todos disparam");
    Rng r1(9), r2(9);
    check(r1.next() == r2.next() && r1.unit() < 1.0 && r1.unit() >= 0.0, "gerador pseudoaleatorio determinista e dentro de [0, 1)");
    double loss = 0;
    Rng r3(4);
    for (int i = 0; i < 100000; i++) loss += r3.unit() < 0.1 ? 1 : 0;
    check(loss > 9500 && loss < 10500, "taxa de perda simulada de 10% fica entre 9,5% e 10,5% em 100 mil amostras");
}

static void test_tracker_state() {
    section("logica do tracker (registro, heartbeat, consulta e expiracao)");
    TrackerState st(1000);
    Manifest m;
    m.name = "filme";
    m.size = 3000;
    m.chunk_size = 1024;
    for (int i = 0; i < 3; i++) m.hashes.push_back(sha_of("k" + std::to_string(i)));
    Digest id = m.id();
    Bitmap full(3);
    for (size_t i = 0; i < 3; i++) full.set(i);
    uint64_t s1 = st.register_peer("seed", "10.0.0.1", 1000, 2000, 0);
    check(s1 != 0 && st.is_active(s1) && st.peer_count() == 1, "registrar um peer cria a sessao");
    check(!st.publish(s1 + 99, m, full.bytes(), 0), "publicar com sessao inexistente e recusado");
    check(!st.publish(s1, m, Bytes{0xFF, 0xFF}, 0), "publicar com bitmap de tamanho errado e recusado");
    check(st.publish(s1, m, full.bytes(), 10) && st.content_count() == 1, "publicar um conteudo valido o coloca no catalogo");
    uint64_t s2 = st.register_peer("leech", "10.0.0.2", 1001, 2001, 20);
    LookupReply lr;
    check(st.lookup(s2, id, lr) && lr.peers.size() == 1 && lr.peers[0].id == "seed" && lr.peers[0].have.full(), "a consulta devolve o seeder e o manifesto");
    check(!st.lookup(s1, id, lr) || lr.peers.empty(), "o proprio peer nao aparece na lista que recebe");
    HeartbeatMsg hb;
    Bitmap partial(3);
    partial.set(0);
    hb.holds.push_back(Holding{id, partial.bytes()});
    hb.uploaded = 5;
    hb.downloaded = 7;
    std::vector<Digest> unknown;
    check(st.heartbeat(s2, hb, 100, unknown) && unknown.empty(), "heartbeat com bitmap parcial e aceito");
    auto list = st.list();
    check(list.size() == 1 && list[0].seeders == 1 && list[0].holders == 2, "catalogo conta 1 seeder (completo) e 2 peers com algum chunk");
    Digest ghost = sha_of("desconhecido");
    HeartbeatMsg hb2;
    hb2.holds.push_back(Holding{ghost, Bytes{1}});
    unknown.clear();
    check(st.heartbeat(s2, hb2, 150, unknown) && unknown.size() == 1 && unknown[0] == ghost, "heartbeat com conteudo desconhecido pede o manifesto ao peer");
    check(st.expire(900) == 0, "dentro do prazo ninguem expira");
    st.heartbeat(s1, HeartbeatMsg{}, 1100, unknown);
    check(st.expire(1200) == 1 && st.peer_count() == 1 && !st.is_active(s2), "peer sem heartbeat alem do prazo e removido");
    check(st.content_count() == 0, "sem nenhum peer com chunks, o conteudo some do catalogo");
    uint64_t s3 = st.register_peer("seed", "10.0.0.9", 1, 2, 1300);
    uint64_t s4 = st.register_peer("seed", "10.0.0.9", 3, 4, 1310);
    check(s4 != s3 && !st.is_active(s3) && st.is_active(s4) && st.peer_count() == 1, "registrar o mesmo id de novo substitui a sessao antiga");
    st.remove(s3, "sessao antiga");
    check(st.is_active(s4), "a limpeza da sessao antiga nao derruba a nova");
    std::string j = st.status_json(1400);
    int depth = 0;
    bool balanced = true;
    for (char ch : j) {
        if (ch == '{' || ch == '[') depth++;
        if (ch == '}' || ch == ']') balanced = balanced && --depth >= 0;
    }
    check(balanced && depth == 0 && j.find("\"peers\":[") != std::string::npos && j.find("\"events\":[") != std::string::npos, "JSON do painel tem estrutura balanceada e os campos esperados");
    check(json_escape("a\"b\\c\n<d>") == "a\\\"b\\\\c\\n<d>" && json_escape(std::string(1, '\x01')) == "\\u0001", "json_escape trata aspas, barras, quebras e controles");
    for (int i = 0; i < 2000; i++) st.register_peer("p" + std::to_string(i), "h", 1, 2, 2000);
    check(st.peer_count() <= kMaxPeers, "o numero de peers registrados respeita o limite");
}

static void test_net_helpers() {
    section("enderecos IPv4 e IPv6 e analise de HOST:PORTA");
    Endpoint ep;
    check(parse_endpoint("127.0.0.1:7000", ep) && ep.host == "127.0.0.1" && ep.port == 7000 && ep.str() == "127.0.0.1:7000", "HOST:PORTA IPv4");
    check(parse_endpoint("[::1]:80", ep) && ep.host == "::1" && ep.port == 80 && ep.str() == "[::1]:80", "[IPv6]:PORTA com colchetes");
    check(parse_endpoint("meu-host.local:65535", ep) && ep.port == 65535, "nome de maquina e porta maxima");
    bool bad = !parse_endpoint("host", ep) && !parse_endpoint("[::1]", ep) && !parse_endpoint(":80", ep) && !parse_endpoint("a:b", ep) && !parse_endpoint("h:0", ep) && !parse_endpoint("h:70000", ep) && !parse_endpoint("::1:80", ep) && !parse_endpoint("h:", ep);
    check(bad, "formas invalidas sao recusadas (sem porta, porta 0 ou acima de 65535, IPv6 sem colchetes)");
    sockaddr_in6 a6;
    std::memset(&a6, 0, sizeof a6);
    a6.sin6_family = AF_INET6;
    a6.sin6_addr.s6_addr[15] = 1;
    a6.sin6_port = htons(443);
    Address v6 = Address::from_sockaddr(reinterpret_cast<sockaddr*>(&a6), sizeof a6);
    check(v6.host() == "::1" && v6.port() == 443 && v6.key() == "::1|443", "formatacao de endereco IPv6");
    sockaddr_in a4;
    std::memset(&a4, 0, sizeof a4);
    a4.sin_family = AF_INET;
    a4.sin_port = htons(9000);
    inet_pton(AF_INET, "192.168.1.7", &a4.sin_addr);
    Address v4 = Address::from_sockaddr(reinterpret_cast<sockaddr*>(&a4), sizeof a4);
    Address mapped = v4.mapped_v6();
    check(v4.host() == "192.168.1.7" && mapped.family() == AF_INET6 && mapped.host() == "192.168.1.7" && mapped.port() == 9000, "IPv4 mapeado em IPv6 volta a ser exibido como IPv4");
    uint16_t tcp_port = 0;
    Fd l = listen_tcp(0, &tcp_port);
    Fd c = connect_tcp(Endpoint{"127.0.0.1", tcp_port}, 1000);
    std::string peer;
    Fd s = accept_tcp(l.get(), 1000, &peer);
    check(c.valid() && s.valid() && peer == "127.0.0.1", "conexao TCP em loopback aceita pelo soquete dual-stack e origem normalizada");
    bool refused = false;
    try {
        Fd l2 = listen_tcp(0, &tcp_port);
        uint16_t closed_port = tcp_port;
        l2.reset();
        connect_tcp(Endpoint{"127.0.0.1", closed_port}, 500);
    } catch (const NetError&) {
        refused = true;
    }
    check(refused, "conexao a uma porta sem servidor falha com NetError");
    UdpSocket u1 = UdpSocket::open(0), u2 = UdpSocket::open(0);
    Address to;
    Address::resolve(Endpoint{"127.0.0.1", u2.port()}, SOCK_DGRAM, to);
    uint8_t msg[] = {1, 2, 3};
    uint8_t buf[16];
    Address from;
    check(u1.send_to(to, msg, 3) && u2.recv_from(buf, sizeof buf, from, 500) == 3 && buf[2] == 3 && from.port() == u1.port(), "datagrama UDP em loopback com origem identificada");
    check(u2.recv_from(buf, sizeof buf, from, 30) == -1, "recv_from sem dados expira");
}

int main() {
    set_log_level(LogLevel::Quiet);
    test_sha256_hmac();
    test_codec();
    test_manifest_store();
    test_channel();
    test_udp_codec();
    test_emulation();
    test_tracker_state();
    test_net_helpers();
    std::printf("\nresultado: %d passaram, %d falharam\n", g_pass, g_fail);
    if (g_fail == 0) std::printf("TODOS OS TESTES PASSARAM\n");
    return g_fail == 0 ? 0 : 1;
}
