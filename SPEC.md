# ZapC — Cliente WhatsApp TUI em C

## 1. Objetivo

Criar um cliente não oficial de WhatsApp, totalmente em terminal, escrito em C,
sem interface gráfica e com foco extremo em baixo consumo de memória.

Desenvolvimento inicial: Debian 13, x86_64, GCC/Clang, Linux moderno.

Objetivo posterior: portar o mesmo código para PlayStation 2 (Linux para PS2,
CPU MIPS R5900 little-endian, ~32 MB de RAM). O software deve ser projetado
desde o primeiro commit levando esse port em consideração.

## 2. Filosofia

O ZapC não tenta reproduzir o WhatsApp Desktop; implementa somente as
funcionalidades essenciais de mensagens.

Prioridades:

1. baixo consumo de RAM;
2. baixo número de dependências;
3. código modular;
4. buffers explicitamente limitados;
5. processamento streaming;
6. funcionamento completo sem GUI;
7. possibilidade de cross-compilation;
8. facilidade de portar para arquiteturas antigas.

Evitar: Electron, Chromium, WebView, JavaScript, Python, Node.js, Qt, GTK, SDL
na interface principal, runtimes pesados, garbage collector.

## 3. Linguagem

C17 (`gcc -std=c17`), preferencialmente também compilando com Clang, com
`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2`. Evitar extensões
específicas do GCC.

## 4. Interface

Exclusivamente em terminal: ANSI escape sequences, stdin, stdout, termios.
Sem ncurses no núcleo. Uma abstração de terminal permite trocar o backend.
Deve funcionar também em modo simples, sem caracteres Unicode de borda.

```
┌───────────────────────────────────────────────┐
│ ZapC                                          │
├───────────────────────────────────────────────┤
│ João                                          │
│                                               │
│ 20:31 João                                    │
│ Você vai hoje?                                │
│                                               │
│ 20:32 Você                                    │
│ Vou sim                                       │
│                                               │
├───────────────────────────────────────────────┤
│ > _                                           │
└───────────────────────────────────────────────┘
```

## 5. Comandos mínimos

`/help /quit /status /connect /disconnect /pair /chats /open <id> /send <texto>
/contacts /mem /debug` — posteriormente `/download /upload /archive /mute /block`.

## 6. Arquitetura

```
Terminal UI
    │
Application
    │
WhatsApp Client ── Session, Messaging, Contacts, Groups, Sync
    │
WhatsApp Protocol ── Binary Nodes, Protobuf, Noise, Signal, JIDs
    │
Transport ── WebSocket, TLS, TCP
    │
Linux sockets
```

Cada camada deve depender o mínimo possível das demais.

## 7–8. Estrutura e dependências

Estrutura `include/zapc/`, `src/{net,wa,storage}/`, `tests/`. Dependências
aceitáveis inicialmente: libc e OpenSSL. O TLS fica atrás de uma interface
abstrata (`tls_connect/tls_read/tls_write/tls_close`) para permitir backends
OpenSSL, mbedTLS, wolfSSL ou BearSSL.

## 9. TLS

TLS 1.2, TLS 1.3 quando disponível, SNI, validação de certificados e de
hostname. Nunca desabilitar validação por padrão. O transporte não depende do
WhatsApp.

## 10. WebSocket

Implementação própria do RFC 6455: HTTP Upgrade, client masking, frames binários
e de texto, ping, pong, close, frames fragmentados, reconnect. Buffers pequenos;
não presumir que um frame inteiro cabe na RAM.

## 11–12. Modelo de memória e buffers

Meta: processo com < 10 MB (desejável 3–8 MB) além do sistema operacional.
Buffers iniciais: input 2 KB, TLS RX/TX 16 KB, WebSocket RX/TX 16 KB, protobuf
scratch 16 KB, 64 mensagens visíveis, 128 contatos, 64 chats — todos alteráveis
em compile-time (`#define ZAPC_NET_RX_SIZE 16384`, etc.).

## 13–14. Streaming e alocação

Nunca baixar tudo para a RAM: socket → buffer de 4–16 KB → parser incremental →
processar → salvar → reutilizar buffer. Vale para histórico, protobuf, mídia,
sincronização e downloads. Reduzir `malloc()` no caminho principal; preferir
buffers fixos, pools e arenas; toda estrutura com limite máximo explícito.

## 15–16. WhatsApp

Compatibilidade com o protocolo de dispositivos vinculados (WhatsApp Web),
usando como referência ZapFast, whatsapp-rust, whatsmeow e Baileys, sem copiar
cegamente. Escopo inicial: pairing, autenticação, persistência da sessão, lista
básica de chats, receber e enviar texto, mensagens diretas, grupos, read
receipts, reconnect, ping/keepalive. Fora do escopo inicial: chamadas, status,
stories, channels, stickers animados, GIF, reações avançadas, comunidades,
localização em tempo real, pagamentos, previews.

## 17. Pairing

Vinculação como companion device por QR (e pairing code se possível), QR
exibido com caracteres no terminal, sessão persistida.

## 18–20. JID, Binary Nodes, Protobuf

Estrutura própria de JID com parser/serializer separados. Representação mínima
e compacta de nós, preferindo views a cópias. Protobuf sem a biblioteca do
Google: decoder próprio, pequeno e adequado a streaming.

## 21–22. Noise e Signal

Noise separado em handshake, cipher state, encrypt, decrypt e key derivation,
usando bibliotecas confiáveis para AES, SHA-256, HKDF, Curve25519 e HMAC.
Signal apenas no necessário: identity keys, signed prekeys, one-time prekeys,
sessions, sender keys, group sessions, encryption e decryption. Nunca registrar
chaves privadas em logs.

## 23–25. Storage, histórico e mídia

Arquivos binários simples em `~/.local/state/zapc/` (`credentials.bin`,
`sessions/`, `contacts.bin`, `chats.bin`, `messages/`), diretório 0700 e
arquivos sensíveis 0600. SQLite opcional no futuro. Histórico: apenas as
últimas 32–64 mensagens da conversa atual em RAM; ao rolar, carregar o bloco
anterior e descartar o distante. Mídia fora do MVP; quando implementada,
mostrar `[Imagem: arquivo.jpg]` etc., download sob demanda direto para disco.

## 26–30. Event loop, logging, configuração, diagnóstico

Event loop single-threaded com `poll()`/`select()` controlando stdin, socket,
timers, reconnect e keepalive. Logs ERROR/WARN/INFO/DEBUG/TRACE (padrão INFO),
nunca registrando senhas, tokens, chaves ou conteúdo descriptografado.
Configuração em `~/.config/zapc/config` (`chave=valor`). `/mem` lê
`/proc/self/status` e mostra RSS, memória virtual e pico. Wrappers
`zap_malloc/zap_calloc/zap_realloc/zap_free` com contadores em builds de debug.

## 31–34. Build, PS2, portabilidade, aleatoriedade

Makefile simples (`make`, `make debug`, `make release`, `make test`,
`make clean`, futuramente `make ps2`). No core, evitar assembly x86, SSE/AVX,
APIs Linux desnecessárias, epoll obrigatório, suposições de endianness e
acessos desalinhados; usar tipos de tamanho fixo e não assumir
`sizeof(long) == 8`. Camada de plataforma (`platform/unix.c`, `platform/ps2.c`)
abstraindo relógio, aleatoriedade, filesystem, terminal, sockets e sleep. RNG
seguro (`getrandom()`); nunca `rand()` para criptografia.

## 35–37. Testes, fuzzing e segurança

Testes para JID, Base64, WebSocket, binary nodes, protobuf, crypto, storage,
Noise e Signal, com test vectors oficiais quando possível. Parsers de rede
preparados para libFuzzer/AFL++. Todo dado da rede é não confiável: verificar
overflow, tamanhos, varints e protobuf malformados, frames WebSocket inválidos,
aninhamento excessivo e payloads grandes demais.

## 38. Etapas

0. Core (main, TUI, config, logging, contadores de memória, event loop)
1. TCP/TLS
2. WebSocket
3. Protocolo binário (JID, nodes, tokens, encoder/decoder)
4. Noise
5. Pairing (QR, credenciais, reconectar sem QR) — primeiro grande marco
6. Receber mensagens
7. Enviar mensagens
8. Grupos
9. History sync em streaming
10. Otimização (< 15 MB RSS no PC, depois < 10 MB)

## 39–40. MVP e definição de sucesso

Compilar no Debian 13, consumir menos de 15 MB, vincular por QR, persistir a
sessão, reconectar, listar chats, receber e enviar texto, funcionar só no
terminal, sem browser nem runtime pesado.

## 41–43. Segunda fase e princípio central

Port para PS2 somente depois do cliente funcional no PC (build 32-bit, TLS
pequeno, cross-compile R5900, profiling). Não objetivos iniciais: WhatsApp
completo, GUI, chamadas, stickers avançados, GIFs, notificações desktop,
múltiplas contas, status, canais, comunidades, galeria, link previews.

> Toda decisão deve responder: isto ainda funcionaria razoavelmente em uma
> máquina de 32 MB de RAM?
