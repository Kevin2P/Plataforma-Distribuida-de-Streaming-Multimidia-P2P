# Especificação do protocolo StreamP2P (versão 1)

Este documento especifica o protocolo usado entre tracker e peers e entre peers. Palavras como DEVE e NÃO DEVE descrevem o que uma implementação precisa fazer para interoperar.

## 1. Convenções

- Inteiros são sem sinal e em ordem de rede (big-endian): `u8`, `u16`, `u32`, `u64`.
- `str`: `u16` com o número de bytes, seguido de bytes UTF-8.
- `blob(max)`: `u32` com o número de bytes (no máximo `max`), seguido dos bytes.
- `digest`: 32 bytes (SHA-256).
- `bitmap(n)`: `ceil(n/8)` bytes; o chunk `i` é o bit `i % 8` do byte `i / 8` (bit menos significativo primeiro); bits além de `n` DEVEM ser zero.
- Toda mensagem malformada (truncada, com bytes sobrando ou com campo acima do limite) DEVE ser descartada e a conexão encerrada.

## 2. Identificadores e limites

| Item | Regra |
|---|---|
| id de peer | 1 a 32 caracteres entre `A-Z a-z 0-9 . _ -` |
| nome de conteúdo | 1 a 64 bytes, UTF-8 válido (sem codificações longas demais, surrogates ou valores acima de U+10FFFF), sem caracteres de controle (U+0000 a U+001F e U+007F a U+009F) |
| tamanho de chunk | de 1024 B a 1 MiB |
| chunks por conteúdo | no máximo 1 048 576 |
| quadro TCP | payload de no máximo 4 MiB; antes do fim do handshake, no máximo 256 bytes |
| peers no tracker | no máximo 1024; conteúdos no máximo 256 |
| anúncios por heartbeat | no máximo 256 conteúdos |
| peers por resposta de consulta | no máximo 512 |

## 3. Manifesto

```
manifesto = nome:str  tamanho:u64  chunk_size:u32  bitrate_kbps:u32  n:u32  hashes:digest[n]
```

- `n` DEVE ser igual a `ceil(tamanho / chunk_size)`, com `n` de 1 a 1 048 576; logo `tamanho` DEVE ser maior que zero e no máximo `chunk_size * 1 048 576`. Um receptor DEVE verificar esses limites antes de somar ou multiplicar, para evitar estouro de inteiro.
- Quem pede um conteúdo por id DEVE conferir que o manifesto recebido tem exatamente esse id.
- O último chunk tem `tamanho - chunk_size * (n - 1)` bytes; os demais têm `chunk_size`.
- `hashes[i]` é o SHA-256 dos bytes do chunk `i`.
- id do conteúdo: `SHA-256("SPM1" || manifesto)`.

Um chunk só DEVE ser aceito (gravado ou entregue) se o seu tamanho e o seu SHA-256 conferem com o manifesto.

## 4. Plano TCP: quadros

```
+-------+--------+------+-------------+-----------+--------+
| 'S''P'| versão | tipo | comprimento | payload   |  MAC   |
|  2 B  |  1 B   | 1 B  |    4 B      | variável  | 32 B   |
+-------+--------+------+-------------+-----------+--------+
```

- `versão` é 1. `comprimento` é o tamanho do payload (no máximo 4 MiB; nos quadros sem MAC do handshake, no máximo 256 bytes, e um receptor DEVE encerrar a conexão ao ver um comprimento maior, sem esperar o payload).
- Os quadros HELLO, CHALLENGE, AUTH e o ERROR anterior ao fim do handshake NÃO levam MAC. Todos os demais levam.

### 4.1 Handshake

Seja `K` a chave compartilhada, `nc` e `ns` nonces aleatórios de 16 bytes, `id` o id do peer.

| Passo | Quadro | Payload |
|---|---|---|
| 1 | cliente envia `HELLO` (1) | `nc` (16 B), `id` (str), `papel` (u8: 0 controle, 1 dados) |
| 2 | servidor envia `CHALLENGE` (2) | `ns` (16 B), `ps` (digest) |
| 3 | cliente envia `AUTH` (3) | `pc` (digest) |
| 4 | servidor envia `AUTH_OK` (4), já com MAC | vazio |

```
ps = HMAC-SHA256(K, "SPv1-server"  || nc || ns || id)
pc = HMAC-SHA256(K, "SPv1-client"  || ns || nc || id)
Ks = HMAC-SHA256(K, "SPv1-session" || nc || ns || id)
```

- O cliente DEVE conferir `ps` antes de enviar `AUTH`. O servidor DEVE conferir `pc`. As comparações DEVEM ser em tempo constante.
- Em caso de falha o servidor PODE enviar `ERROR` (5) sem MAC e DEVE fechar a conexão.
- O handshake tem prazo de 3 s por etapa: cada quadro esperado (`HELLO` e `AUTH` no servidor, `CHALLENGE` e `AUTH_OK` no cliente) DEVE chegar inteiro, do primeiro ao último byte, nesse prazo; caso contrário, a conexão é encerrada.
- Um servidor de controle DEVE recusar `papel` diferente de 0, e um servidor de dados DEVE recusar `papel` diferente de 1.

### 4.2 MAC por quadro

```
MAC = HMAC-SHA256(Ks, direção:u8 || contador:u64 || cabeçalho (8 B) || payload)
```

- `direção` é 0 para quadros do cliente e 1 para quadros do servidor.
- `contador` não é transmitido: cada lado mantém um contador de quadros enviados e um de recebidos, ambos iniciados em 0 no primeiro quadro com MAC (o `AUTH_OK` do servidor é o seu quadro 0).
- Um MAC inválido (adulteração, repetição ou reordenação) DEVE encerrar a conexão.

## 5. Mensagens do plano de controle (cliente é o peer, servidor é o tracker)

O primeiro quadro após o handshake DEVE ser `REGISTER`, em até 5 s.

| Cód. | Nome | Payload |
|---|---|---|
| 10 | `REGISTER` | `porta_tcp_dados:u16`, `porta_udp_dados:u16` |
| 11 | `REGISTER_OK` | `intervalo_heartbeat_ms:u32`, `ttl_ms:u32` |
| 12 | `PUBLISH` | `manifesto`, `bitmap:blob` |
| 13 | `PUBLISH_OK` | vazio |
| 14 | `HEARTBEAT` | `enviados:u64`, `recebidos:u64`, `n:u16`, `n` x (`id_conteudo:digest`, `bitmap:blob`) |
| 15 | `HEARTBEAT_OK` | `n:u16`, `n` x `id_conteudo:digest` (conteúdos que o tracker não conhece) |
| 16 | `LIST` | vazio |
| 17 | `LIST_REPLY` | `n:u16`, `n` x (`id`, `nome:str`, `tamanho:u64`, `chunk_size:u32`, `bitrate:u32`, `chunks:u32`, `seeders:u32`, `holders:u32`) |
| 18 | `LOOKUP` | `id_conteudo:digest` |
| 19 | `LOOKUP_REPLY` | `manifesto`, `n:u16`, `n` x (`id:str`, `host:str`, `porta_tcp:u16`, `porta_udp:u16`, `bitmap:blob`) |
| 20 | `BYE` | vazio |
| 5 | `ERROR` | `motivo:str` |

Regras:

- O endereço de um peer é o endereço de origem da conexão de controle, como o tracker o observa (um IPv4 mapeado em IPv6 é normalizado para IPv4). O peer informa apenas as portas.
- Um peer envia `HEARTBEAT` a cada `min(intervalo_heartbeat_ms, 200 ms)`. O `HEARTBEAT` substitui por completo os anúncios anteriores do peer.
- Se o `HEARTBEAT_OK` listar conteúdos desconhecidos, o peer DEVE enviar `PUBLISH` para cada um (isso reconstrói o catálogo depois da queda do tracker).
- O tracker DEVE considerar um peer caído quando a conexão fecha ou quando passam mais de `ttl_ms` sem heartbeat.
- Um novo `REGISTER` com o mesmo id substitui a sessão anterior.
- Um conteúdo sem nenhum peer com algum chunk DEVE ser removido do catálogo.
- `LOOKUP` não devolve o próprio peer que pergunta nem peers sem chunks.
- Um `LOOKUP` de conteúdo desconhecido recebe `ERROR` e a sessão continua.

## 6. Plano de dados por TCP (papel 1)

| Cód. | Nome | Payload |
|---|---|---|
| 30 | `CHUNK_REQ` | `id_conteudo:digest`, `indice:u32` |
| 31 | `CHUNK_DATA` | `indice:u32`, `dados:blob(1 MiB)` |
| 32 | `CHUNK_ERR` | `codigo:u8` (1 = o peer não tem o chunk) |

Requisições e respostas seguem a ordem do TCP, uma resposta por requisição. O servidor fecha conexões ociosas por mais de 60 s.

## 7. Plano de dados por UDP

Datagrama:

```
+-------+--------+------+--------+----------+--------+
| 'S''U'| versão | tipo | reqid  | corpo    | MAC    |
|  2 B  |  1 B   | 1 B  | 8 B    | variável | 16 B   |
+-------+--------+------+--------+----------+--------+
MAC = HMAC-SHA256(Ku, todos os bytes anteriores)[0..16),  Ku = HMAC-SHA256(K, "SPv1-udp")
```

| Tipo | Nome | Corpo |
|---|---|---|
| 1 | `REQ` | `id_conteudo:digest`, `indice:u32` |
| 2 | `DATA` | `fragmento:u16`, `total:u16`, `tamanho_chunk:u32`, bytes (1200 B, exceto o último fragmento) |
| 3 | `ACK` | `n:u8`, `bitmap` de `n` bytes com os fragmentos recebidos |
| 4 | `ERR` | `codigo:u8` (1 = não tem o chunk, 2 = ocupado) |

- Datagramas com MAC inválido, tamanho inválido ou `reqid` desconhecido DEVEM ser descartados em silêncio.
- `total` DEVE ser `ceil(tamanho_chunk / 1200)`.
- Transferência: o leecher escolhe `reqid` (64 bits) e envia `REQ`. O peer lê o chunk, envia todos os fragmentos `DATA` e mantém o estado da transferência, chaveado por (endereço do leecher, `reqid`).
- O leecher responde a cada `DATA` novo ou duplicado com um `ACK` com o bitmap acumulado. Terminado o chunk, envia o `ACK` completo duas vezes.
- O peer retransmite um fragmento ainda não confirmado (a) ao receber um `ACK` que confirma um fragmento de índice maior, se o último envio foi há mais de `RTO/2`; ou (b) quando passa `RTO` desde o último envio, com `RTO` multiplicado por 2 a cada rodada de retransmissão, até 8 vezes o valor inicial.
- O peer abandona a transferência após 25 rodadas de retransmissão ou 20 s. O peer aceita no máximo 512 transferências simultâneas.
- Sem nenhum `DATA`, o leecher reenvia o `REQ` a cada `RTO`; com `DATA` parcial, reenvia o `ACK` a cada `RTO`. Desiste da transferência após 2 s.
- `RTO` inicial: 100 ms (configurável).

## 8. Segurança

Garantias: somente quem conhece `K` completa o handshake; mensagens TCP adulteradas, repetidas ou reordenadas são detectadas; datagramas UDP adulterados são descartados; chunks são verificados contra o manifesto.

Não garantidas: autenticidade do campo `papel` do `HELLO` (ele não entra nas provas; um intermediário pode alterá-lo, o que só causa a recusa da conexão); confidencialidade (nada é cifrado); sigilo perfeito de encaminhamento; identidade individual (todos os membros compartilham `K`); proteção de datagramas UDP contra repetição (inofensiva para a integridade, pois todo chunk é verificado por hash).

## 9. Versionamento

A versão está no cabeçalho. Um receptor DEVE descartar mensagens de versão desconhecida.
