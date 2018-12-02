package srv;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */

/* Thread which will manage the Client and Server interaction after the connection between them */
public class Point extends Thread {

    private final Socket socket;
    private int id;
    private String modo;
    private String key;
    private IvParameterSpec ivspec;

    public Point(int id, Socket socket){
        this.id = id;
        this.socket = socket;
        this.key = "SDCSSI2015123456";
    }


    @Override
    public void run() {
        System.out.println ("(Point, Socket)" + "(" + this.id + "," + this.socket.toString() + ")" );

        try {
            DataInputStream dis = new DataInputStream(socket.getInputStream());

            /* Reading the name and cipher modes (if any) intended by the client. */
            byte[] modoClient = new byte[dis.available()];
            dis.read(modoClient);
            modo = new String(modoClient);

            /* Creation of a SecretKeySpec with the cipher name. */
            String[] modos = modo.split("/");
            SecretKeySpec skey = new SecretKeySpec(key.getBytes(),modos[0]);

            /* Case the client intends a cipher with modes, is also readed the desired Initialization Vector(IV). */
            if(modos.length > 1) {
                byte[] iv = new byte[16];
                dis.read(iv);
                ivspec = new IvParameterSpec(iv);
            }

            /* Initialization of cipher with the obtained values. */
            Cipher cipher = Cipher.getInstance(modo);
            if(modos.length == 1) {
                cipher.init(Cipher.DECRYPT_MODE, skey);
            }
            else {
                cipher.init(Cipher.DECRYPT_MODE, skey, ivspec);
            }

            CipherInputStream cis = new CipherInputStream(this.socket.getInputStream(), cipher);

            int input = 1;
            StringBuilder message = new StringBuilder();

            /* Reading the chars sended by the Client to a String Builder.
               When a '\n' is found, the message is printed and the String Builder is reseted.
             */
            while(input != -1){
                while((input = cis.read()) != -1) {
                    /* Before the message, is inserted the client id */
                    if(message.length() == 0) {
                        message.append(this.id + ": ");
                    }

                    message.append((char) input);
                    if(input == (int) '\n') {
                        System.out.print(message.toString());
                        message.setLength(0);
                        break;
                    }
                }
            }

            System.out.println("Client " + this.id + " disconnected !");
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}