## Guião 3
### Descrição

O objectivo deste guião é implementar o protocolo de acordo de chaves Diffie-Hellman.

### Classes
- No package DH está uma versão sequencial do protocolo com 2 agentes.
- No package srv está implementado o protocolo num ambiente distribuído. Num contexto de Cliente-Servidor, cada Cliente conecta-se ao Servidor e troca mensagens até que o acordo da chave se termine. É garantido confidencialidade na troca de mensagens através da implementação de uma cifra simétrica.