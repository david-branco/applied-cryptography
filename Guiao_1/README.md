## Guião 1
#### /scripts
Scripts responsáveis pela invocação dos jars de cada main.

    Alínea 1
        scripts/server.sh
        scripts/client.sh
    Alínea 2
        scripts/rc4.sh
        scripts/rc4test.sh
    Alínea 3
        scripts/ourrc4.sh

(listagem presente no ficheiro guiao1.sh)

#### /src/src_rc4
Código relativo ao problema do RC4 (alínea 2 do guião).
A classe RC4.java tem dois métodos :
- *genkey*: gera uma chave de aleatória e guarda num ficheiro em modo binário que é passado como argumento.
- *operation*: permite cifrar o conteúdo de um ficheiro (através de um determinada chave que é passada como argumento) e guardar o texto cifrado em outro ficheiro. Permite também decifrar o conteúdo de um ficheiro de forma análoga. Deste modo *operation* tem um argumento adicional de forma a escolher o modo de utilização (encrypt "-enc", decrypt "-dec").
             
#### /src/srv_srv
Código seguindo o modelo implementação Server-Client, optando por utilizar 1 Thread por cliente (alínea 1 do guião).
  
    - Server.java : Classe responsável pela aceitação de pedidos de conexão dos clientes. Cria também threads (Point.java) que se responsabilizam por cada cliente.
    
    - Client.java : Classe responsável pela interface do cliente.

#### /src/main
Casses de execução de todos os sub projectos:

    - Main_client;
    - Main_server;
    - Main_rc4;
    - Main_OurRC4.

#### /src/Rc4_test.java
Classe de teste aos métodos da classe RC4.
    
- Foi definido um conjunto de strings;
- Cada string é guardada num ficheiro de texto;
- É gerada uma chave por cada ficheiro de texto;
- Cada ficheiro de texto é cifrado com uma chave;
- É decifrado com a mesma chave;
- No final o texto limpo é comparado com texto cifrado.

#### /src/src_ourrc4 :   
   Implementação de uma cifra RC4 baseada em algoritmos descritos nos slides da disciplina (alínea 3 do guião). 
