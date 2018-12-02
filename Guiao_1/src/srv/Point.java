package srv;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */

/* Thread which will manage the Client and Server interaction after the connection between them */
public class Point extends Thread {

    private final Socket socket;
    private int id;

    public Point(int id, Socket socket){
        this.id = id;
        this.socket = socket;
    }

    @Override
    public void run() {
        System.out.println ("(Point, Socket)" + "(" + this.id + "," + this.socket.toString() + ")" );

        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));

            while(true){
                String input = in.readLine();
                if (input == null){
                    System.out.println("Client "+ id + " disconnected !");
                    break;
                }

                System.out.println(this.id + ": " + input);
            }
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
