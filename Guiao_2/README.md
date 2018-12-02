## Guião 2
### Descrição
Para a realização deste guião foi reutilizado o modelo Server-Client implementado para o guião 1.

Através do Cliente criado temos a capacidade de configurar a cifra que queremos utilizar. Essa informação será enviada ao Servidor numa fase prévia à comunicação propriamente dita. O Servidor recebe a informação relativa à cifra a utilizar e depois está apto a receber as mensagens do Cliente, decifrar e imprimir as mesmas.

O objectivo é garantir confidencialidade nas comunicações entre o Cliente e o Servidor e analisar o impacto nas questões de buffering e sincronização das seguintes cifras :

    RC4
    AES/CBC/NoPadding
    AES/CBC/PKCS5Padding
    AES/CFB8/PKCS5Padding
    AES/CFB8/NoPadding
    AES/CFB/NoPadding


### Classes
     
#### Servidor
    Guiao_2/src/main/Main_server.java
        Classe que inicia o Servidor dados 2 parâmetros : Host e Port.

    Guiao_2/src/srv/Server.java
        Cria o ServerSocket e fica à espera de pedidos de conexão de Clientes.
        Assim que detecta alguma conexão, atribui-lhe um ID e cria uma Thread (classe Point) que vai gerir a iteração com o respectivo Cliente.

    Guiao_2/src/srv/Point.java
        Faz a gestão da ligação entre Servidor e Cliente após a conexão.          
        Lê do socket alguns dados de configuração da cifra (nome e modos da cifra, vector de inicialização).
        Inicia a mesma e por fim cria um CipherInputStream que vai receber mensagens cifradas do Cliente e as vai imprimir decifradas juntamente com o ID do Cliente. 

#### Cliente
     ### Guiao_2/src/main/Main_client.java
        Classe que inicia o Cliente dados 3 parâmetros obrigatórios: Host, Port e nome da cifra, e como parâmetros opcionais os modos da cifra (caso assim pretenda).

     Guiao_2/src/srv/Client.java
        Conecta-se ao servidor via socket, e envia-lhe dados de configuração da cifra que pretende utilizar (nome e modos da cifra, vector de inicialização). Caso seja necessário um Vector de Inicialização, gere um de 16 posições aleatoriamente e de forma não linear.
        Por fim envia ao Servidor as mensagens inseridas pelo Utilizador no seu terminal.

### Análise
#### RC4
- Cifra sequencial
- Cifra de chave de tamanho variável.

A implementação desta cifra no cenário de troca de mensagens num ambiente distribuído não apresenta grandes dificuldades.
Cada mensagem enviada, independentemente do tamanho, é cifrada e decifrada pela cifra.

#### AES (Advanced Encryption Standard)            
- Cifra com de bloco variável.
- Cifra com chave variável.
Baseia-se no processamento de um estado de 16 bytes.<br>

A cifra AES pode ser implementada seguindo vários modos :
- CBC (Cipher Block Chaining)
    * É necessário a inicialização de um vector para combinar com o primeiro bloco; 
    * Utilizou-se o SecureRandom para iniciar um array de bytes de 16 unidades aleatoriamente;
    * O array é utilizado para gerar um objecto do tipo IVParameterSpec; 
    * A chave e o objecto deste tipo são argumentos para inicializar a cifra.

- CFB (Cipher Feedback Mode) e CFB8 (Cipher Feedback Mode)
    * Neste módulo é utilizado de forma análoga ao CBC, do ponto de vista de implementação.

#### Modos Padding utilizados
NoPadding
- Os modos implementados com NoPadding requerem mais cuidado. 
- Do lado do Servidor, o objecto CypherInputStream faz buffering até o conteúdo recebido atingir valores múltiplos de 16 bytes. 
- Quando ocorre, imprime a mensagem cifrada.

PKCS5Padding
- Modo de padding é o recomendado na norma PKCS#5 e é o mais utilizado.
- Não apresenta as limitações do NoPadding. Através deste modo o servidor decifra cada mensagem enviada, independentemente do seu tamanho.   