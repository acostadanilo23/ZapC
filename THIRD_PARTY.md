# Terceiros e referências

O ZapC é uma implementação própria em C. Nenhum código das referências abaixo
foi copiado literalmente, exceto onde indicado.

| Origem | Uso no ZapC | Licença |
|---|---|---|
| [whatsapp-rust](https://github.com/oxidezap/whatsapp-rust) | O dicionário de tokens do formato binário (`src/wa/tokens_table.h`) foi gerado a partir de `wacore/binary/src/tokens.json` com `tools/gen_tokens.py`. Referência de protocolo e arquitetura. | MIT |
| [TweetNaCl](https://tweetnacl.cr.yp.to/) | A aritmética de corpo/grupo de Curve25519/Ed25519 em `src/crypto/curve25519.c` segue a estrutura do TweetNaCl. | Domínio público |
| [whatsmeow](https://github.com/tulir/whatsmeow) | Referência de comportamento do protocolo (handshake, pareamento, nós). Nenhum código copiado. | MPL-2.0 |
| [libsignal](https://github.com/signalapp/libsignal) | Referência dos formatos e KDFs do Signal Protocol / XEdDSA. Nenhum código copiado. | AGPL/GPL (apenas como especificação) |
| [Nayuki QR Code generator](https://www.nayuki.io/page/qr-code-generator-library) | Referência do algoritmo de QR code (tabelas da norma ISO/IEC 18004). Nenhum código copiado. | MIT |
| OpenSSL | Backend de TLS e de primitivas simétricas (AES, SHA, HMAC). | Apache-2.0 |

A chave pública raiz do certificado Noise do WhatsApp (`WA_CERT_PUBKEY` em
`src/wa/client.c`) é um dado do protocolo.
