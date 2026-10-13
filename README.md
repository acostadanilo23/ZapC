# ZapC

Cliente **não oficial** de WhatsApp para terminal, escrito em C17, com foco
extremo em baixo consumo de memória. Desenvolvido no Linux x86_64 e projetado
desde o início para ser portado ao PlayStation 2 (MIPS R5900, ~32 MB de RAM).

Veja [SPEC.md](SPEC.md) para a especificação completa.

> **Aviso:** o ZapC não é afiliado ao WhatsApp/Meta. Usar clientes não
> oficiais pode violar os termos de serviço do WhatsApp e levar ao banimento
> da conta. Use por sua conta e risco.

## Compilar

Dependências: um compilador C17 (GCC ou Clang), `make` e OpenSSL (`libssl-dev`).

```sh
sudo apt install build-essential libssl-dev   # Debian/Ubuntu
make            # build padrão (-O2)       -> build/default/zapc (e ./zapc)
make release    # -Os, sem símbolos         -> build/release/zapc
make debug      # -O0, ASan/UBSan, contadores de alocação
make test       # testes unitários
make clean
```

Limites de buffers podem ser alterados em tempo de compilação, por exemplo:

```sh
make CFLAGS_EXTRA="-DZAPC_WA_FRAME_MAX=131072 -DZAPC_VISIBLE_MESSAGES=32"
```

Todos os limites ficam em [`include/zapc/build_config.h`](include/zapc/build_config.h).

## Usar

```sh
./zapc               # tela cheia
./zapc --plain       # modo linha (bom para terminais simples e scripts)
./zapc --ascii       # bordas ASCII, sem Unicode
```

Na primeira execução o ZapC conecta e mostra um QR code. No celular abra
**WhatsApp → Aparelhos conectados → Conectar um aparelho** e escaneie. A sessão
fica salva e as próximas execuções reconectam sem QR.

| Comando | Ação |
|---|---|
| `/help` | ajuda |
| `/connect`, `/disconnect` | conectar / desconectar |
| `/pair` | (re)exibir o QR de vinculação |
| `/status` | estado da conexão, conta, TLS, contadores |
| `/chats` | lista de conversas |
| `/open <n \| telefone \| jid>` | abrir conversa (ex.: `/open 1`, `/open 5511999998888`) |
| `/send <texto>` ou só digitar | enviar para a conversa aberta |
| `/close` (ou Esc) | fechar a conversa |
| `/contacts` | contatos conhecidos (nomes recebidos) |
| `/mem` | RSS, pico, heap e buffers fixos |
| `/debug` | alterna log DEBUG e mostra as últimas linhas |
| `/logout` | desvincular este aparelho |
| `/quit` (ou Ctrl-C) | sair |

PgUp/PgDn e ↑/↓ rolam o histórico; blocos antigos são lidos do disco sob demanda.

### Configuração

`~/.config/zapc/config` (ou `--config arquivo`), formato `chave=valor`:

```ini
log_level=info            # error|warn|info|debug|trace
history_cache=64          # mensagens carregadas por conversa
ascii=0
color=1
device_name=ZapC          # nome mostrado em "Aparelhos conectados"
download_dir=/home/user/Downloads
keepalive=25              # segundos
wa_version=2.3000.1049558099
# wa_host=web.whatsapp.com
# ca_file=/caminho/para/ca-bundle.crt
```

Também é possível usar `--set chave=valor` na linha de comando.

### Arquivos

Estado em `~/.local/state/zapc/` (diretório 0700, arquivos 0600):

```
credentials.bin   chaves do aparelho e dados do pareamento
prekeys.bin       one-time prekeys do Signal
sessions/         sessões Signal (uma por aparelho remoto)
identities/       chaves de identidade remotas
senderkeys/       sender keys de grupos
chats.bin         lista de conversas
contacts.bin      nomes de contatos
messages/*.log    histórico (append-only, lido em blocos)
zapc.log          log
```

## Arquitetura

```
src/main.c, app.c, terminal.c      UI, comandos, event loop (poll)
src/wa/client.c                    conexão, handshake Noise, dispatch, keepalive
src/wa/pairing.c                   pareamento por QR
src/wa/message.c                   receber/enviar mensagens, receipts, prekeys
src/wa/signal.c                    X3DH, Double Ratchet, sender keys
src/wa/noise.c                     Noise_XX_25519_AESGCM_SHA256
src/wa/binary_node.c, tokens.c     formato binário de nós + dicionário
src/wa/protobuf.c                  leitor/escritor protobuf mínimo
src/wa/frame.c                     frames com prefixo de 3 bytes
src/net/websocket.c                RFC 6455 próprio, recepção em streaming
src/net/tls_openssl.c, tcp.c       TLS atrás de interface abstrata
src/crypto/                        backend OpenSSL + Curve25519/XEdDSA portátil + inflate
src/storage/                       credenciais, sessões, histórico
src/platform/unix.c                relógio, RNG, arquivos, /proc
src/qr.c                           gerador de QR code
```

Princípios: um único thread, sem alocação no caminho principal (buffers fixos e
uma arena por frame), todo dado da rede tratado como não confiável (tamanhos,
varints, profundidade de aninhamento), chaves privadas nunca vão para o log.

## Estado

| Etapa da SPEC | Situação |
|---|---|
| 0 Core (TUI, config, log, memória, event loop) | feito |
| 1 TCP/TLS (SNI, verificação de certificado e hostname) | feito (OpenSSL) |
| 2 WebSocket RFC 6455 | feito |
| 3 Protocolo binário (JID, nós, tokens) | feito |
| 4 Noise (com verificação da cadeia de certificados) | feito |
| 5 Pareamento por QR, credenciais, reconexão sem QR | feito |
| 6 Receber mensagens (texto; mídia mostrada como `[Imagem]` etc.) | feito |
| 7 Enviar mensagens + confirmações (✓ enviado, ✓✓ entregue/lido) | feito |
| 8 Grupos (receber, enviar, nomes) | feito |
| 9 History sync em streaming | feito (últimas 32 mensagens por conversa) |
| 10 Otimização | em andamento |

**Importante:** todo o protocolo foi testado localmente, mas ainda **não**
contra os servidores reais do WhatsApp (o ambiente de desenvolvimento não
tinha acesso à rede do WhatsApp). O que foi verificado:

- primitivas criptográficas com vetores oficiais (RFC 7748, 5869, 4231) e as
  assinaturas XEdDSA validadas pelo Ed25519 do OpenSSL;
- compatibilidade byte a byte do Signal (X3DH nos dois papéis, ratchet,
  mensagens fora de ordem, sender keys) contra o **python-axolotl**, uma
  implementação independente da libsignal (`make interop`);
- QR codes idênticos, módulo a módulo, aos de uma biblioteca independente;
- um teste ponta a ponta (`tests/test_integration.c`) com um servidor falso
  que fala TLS + WebSocket + Noise e conduz o cliente real por pareamento,
  reinício 515, login, upload de prekeys, mensagens diretas nos dois sentidos
  (incluindo o próprio celular), grupos nos dois sentidos e history sync
  baixado por HTTPS.

Os formatos de mensagens e nós seguem as referências (whatsmeow,
whatsapp-rust), mas detalhes que só o servidor real valida podem precisar de
ajuste no primeiro uso. Se a conexão falhar, rode com `--log-level debug` (ou
`trace`, que mostra os nós trocados, sem conteúdo cifrado) e veja
`~/.local/state/zapc/zapc.log`. Se o servidor recusar a versão (erro 405), o
ZapC busca automaticamente a versão atual em `web.whatsapp.com/sw.js`.

Ainda não implementado: download/upload de mídia (`/download`, `/upload`),
retry de mensagens que o destinatário não conseguiu decifrar, app state sync
(nomes de contatos da agenda, arquivar, silenciar), pairing code, chamadas.

### Memória

Medido no x86_64 (build release, binário de ~200 KB sem símbolos):

- ocioso: ~3,7 MB de RSS (incluindo as bibliotecas do OpenSSL);
- teste ponta a ponta completo (pareamento, mensagens, grupos, history sync):
  pico de ~9,5 MB no processo de teste inteiro.

Os maiores buffers fixos: frame Noise (256 KB), descompressão de frames
(256 KB), arena de nós (64 KB), envelopes de envio (96 KB), history sync
(~110 KB). Todos ajustáveis em `build_config.h`; num port para o PS2, trocar o
OpenSSL por um TLS pequeno reduz bastante o total.

## Testes

```sh
make test          # unitários + ponta a ponta (servidor falso)
make debug test    # o mesmo com ASan/UBSan (MODE=debug)
make interop       # compatibilidade Signal com python-axolotl (pip install python-axolotl)
make fuzz          # alvos libFuzzer (clang + compiler-rt)
```

## Licença

MIT. Veja [LICENSE](LICENSE) e [THIRD_PARTY.md](THIRD_PARTY.md).
