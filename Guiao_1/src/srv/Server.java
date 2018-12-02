package srv;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */
public class Server extends  Thread {
    private final String host;
    private final int port;
    private ServerSocket ss = null;

    public Server (String host, int port){
        this.host = host;
        this.port = port;
    }

    @Override
    public void run() {
        try {
            this.ss = new ServerSocket(this.port);
            System.out.println("Server is ready !");
            int clientNumber = 0;
            while(true) {
                clientNumber++;
                Socket socket = this.ss.accept();
                Point p = new Point(clientNumber, socket);
                p.start();

                System.out.println("Client " + clientNumber + " connected !");
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
