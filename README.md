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

Veja a seção de estado detalhado no fim deste arquivo.

## Licença

MIT. Veja [LICENSE](LICENSE) e [THIRD_PARTY.md](THIRD_PARTY.md).
