<div align="center">

# StreamP2P

**Plataforma distribuída de streaming multimídia P2P com segurança e tolerância a falhas**

Trabalho Final · IME-USP · Kevin Miyahara Omori e Christian Laurence Almeida Barry

</div>

Um tracker mantém o catálogo e a lista de peers. Os peers publicam arquivos e trocam chunks de 16 KiB verificados por SHA-256, por TCP ou por UDP com confiabilidade própria, e toda a comunicação é autenticada com HMAC-SHA256. O programa é C++20 sobre soquetes POSIX, sem bibliotecas externas. O protocolo está especificado em [`docs/PROTOCOL.md`](docs/PROTOCOL.md), e o projeto e os resultados estão no relatório (`report.pdf`).

## Requisitos

Linux, `g++`, `make` e Python 3. Opcionais: `ffmpeg` (vídeo real), `matplotlib` (figuras dos experimentos), `iproute2` e `ethtool` (experimento com netem, como root). No Ubuntu:

```bash
sudo apt install g++ make python3 ffmpeg python3-matplotlib iproute2 ethtool
```

## Compilar e testar

```bash
make
make test
```

`make` gera `bin/streamp2p`. `make test` roda 85 testes unitários e 115 verificações de integração com processos reais, em cerca de 2 minutos. O teste de IPv6 e o de vídeo real são pulados, com aviso, se o kernel não tiver IPv6 ou se o `ffmpeg` não estiver instalado. `make fuzz` roda o fuzzer autenticado e de carga (38 verificações, em cerca de um minuto e meio): mensagens com MAC válido e conteúdo malformado contra o tracker e o seeder, seeders maliciosos contra o leecher, conexões lentas, 300 peers simultâneos e a saturação do painel. `make sanitize` e `make tsan` repetem a suíte e o fuzzer com ASan e UBSan e com TSan.

## Usar

Todos os processos compartilham uma chave, dada por `-k` ou pela variável `STREAMP2P_KEY`. `./bin/streamp2p -h` lista todas as opções. As mensagens no terminal são ASCII, sem acentos.

```bash
export STREAMP2P_KEY=chave-demo
./bin/streamp2p tracker -p 7000 -w 8080 &
./bin/streamp2p gen -o filme.bin -s 4194304
./bin/streamp2p seed -t 127.0.0.1:7000 -f filme.bin -n filme -i seed1 -b 4000 &
sleep 1
./bin/streamp2p list -t 127.0.0.1:7000
./bin/streamp2p get -t 127.0.0.1:7000 -n filme -i v1 -o copia.bin
sha256sum filme.bin copia.bin
```

O `get` reproduz o conteúdo a 4 Mbit/s (o `-b` do seed), imprime uma linha `RESULT` com as métricas e grava `copia.bin`, que deve ter o mesmo hash do original. O painel web fica em `http://localhost:8080`. Com o tracker ainda no ar:

```bash
# UDP com 10% de perda nos dois sentidos (cerca de 15 s); -N mede a vazão, sem ritmo de reprodução
./bin/streamp2p seed -t 127.0.0.1:7000 -f filme.bin -n perda -i seed2 -l 0.1 -D 20 &
sleep 1
./bin/streamp2p get -t 127.0.0.1:7000 -n perda -i v2 -m udp -l 0.1 -N -o copia2.bin

# falha: dois seeders de 3 Mbit/s; um morre aos 2 s e o download termina com o outro
./bin/streamp2p seed -t 127.0.0.1:7000 -f filme.bin -n falha -i a -r 3000 & A=$!
./bin/streamp2p seed -t 127.0.0.1:7000 -f filme.bin -n falha -i b -r 3000 &
sleep 1
./bin/streamp2p get -t 127.0.0.1:7000 -n falha -i v3 -N -o copia3.bin &
sleep 2; kill -9 $A; wait $!
sha256sum filme.bin copia2.bin copia3.bin

# vídeo real tocando enquanto é baixado: -s entrega em ordem, no ritmo da reprodução
ffmpeg -v error -f lavfi -i testsrc=size=640x360:rate=25 -f lavfi -i sine -t 20 -c:v mpeg2video -b:v 1500k -c:a mp2 -f mpegts video.ts
./bin/streamp2p seed -t 127.0.0.1:7000 -f video.ts -n video -i seedv -b 2500 &
sleep 1
./bin/streamp2p get -t 127.0.0.1:7000 -n video -i v4 -s - | ffplay -autoexit -

# encerra tracker e seeders e apaga os arquivos da demonstração e os chunks guardados por cada peer
kill $(jobs -p); rm -rf store-* filme.bin copia*.bin video.ts
```

## Refazer as medições

Os CSVs de `results/` são os dados do relatório; `python3 scripts/make_assets.py` gera a partir deles as tabelas, as figuras e os números citados no texto, em `report/generated/`. Para refazer as medições, que variam alguns por cento entre execuções:

```bash
python3 scripts/run_experiments.py
sudo scripts/netem_loss.sh
```

O primeiro comando refaz os 9 experimentos que usam o emulador do programa, em cerca de 15 minutos; `python3 scripts/run_experiments.py swarm` refaz só um (`chunk delay loss rto swarm p2p faults prebuffer ttl`). O segundo mede TCP contra UDP com perda aplicada pelo kernel, em cerca de 10 minutos, dentro de um namespace de rede próprio, sem afetar o resto da máquina.

## Estrutura

```
src/        código-fonte (C++20)
tests/      testes unitários
scripts/    testes de integração e de conformidade, fuzzer, experimentos e geração de figuras
docs/       especificação do protocolo
results/    CSVs dos experimentos
```
