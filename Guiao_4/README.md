## Guião 4
### 1ª Fase
#### Descrição
Este guião tem como objectivo evitar ataques Man-in-the-Midle ao qual o protocolo Diffie-Helman é vulnerável. Isto significa, que o servidor está vulnerável a acordar chaves com um intruso. Como tal será acrescentado alguns passos que constituem um protocolo designado por Station-to-Station.

O protocolo Station-to-Station acrescenta os seguintes passos ao acordo de chaves Diffie-Helman:
- Uma vez acordada a chave de sessão o agentes assinam o par ordenado (X,Y);
- As assinaturas são trocadas entre os agentes, cifradas com um par de chaves RSA que foram acordadas previamente;
- O protocolo termina com sucesso se as assinaturas forem recuperadas e verificadas correctamente.

#### Implementação
Foi adicionado código ao guião 3 correspondente aos passos do protocolo Station-to-Station.

### 2ª Fase
#### Descrição 
O segundo objectivo deste guião é o uso de certificados X509.
Um certificado de chave pública é uma estrutura de dados que associa uma chave pública a um determinado agente. 
A assinatura da Autoridade de Certificação, entidade que emite certificados, assegura a autenticidade e integridade do certificado.

Os certificados são utilizados principalmente na validação de informação assinada digitalmente. É possível usar os certificados para efeitos de confidencialidade, contudo surgem problemas de eficiência.

#### Implementação
No mesmo contexto de Servidor-Cliente, ambos os agentes têm um certificado. O primeiro passo entre estes agentes é a troca de certificados e a respectiva validação para assegurar autenticidade.
A seguir segue-se o protocolo Diffie-Helman, mas a troca de mensagens é assinada por cada uma das partes.