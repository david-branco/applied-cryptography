package srv;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */
public class Client extends Thread {
    private final String host;
    private final int port;
    private Socket socket;

    public Client(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @Override
    public void run() {
        try {
            this.socket = new Socket(this.host,this.port);
            System.out.println("Connected with success !");

            PrintWriter out = new PrintWriter(this.socket.getOutputStream());
            BufferedReader input_reader = new BufferedReader(new InputStreamReader(System.in));

            while(true){
                String input = input_reader.readLine();
                if (input == null) break;
                out.println(input);
                out.flush();
            }

            System.out.println("Connection Finished !");
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
