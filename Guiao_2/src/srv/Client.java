package srv;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */

/* Class which exchange encrypted messages with a server. */
public class Client extends Thread {
    private final String host;
    private final int port;
    private Socket socket;

    private SecretKeySpec skey;
    private String[] modos;
    private Cipher cipher;

    public Client(String host, int port, String[] modos) {
        this.host = host;
        this.port = port;

        this.modos = modos;
        this.skey = new SecretKeySpec("SDCSSI2015123456".getBytes(),modos[0]);
    }

    @Override
    public void run() {
        try {
            this.socket = new Socket(this.host,this.port);
            System.out.println("Connected with success !");

            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

            /* If the used cipher in client has no modes, then it is initialized
            only with its name and secret key. */
            if(modos.length == 1) {
                /* Tell the server the cipher name. */
                dos.write(modos[0].getBytes());
                cipher = Cipher.getInstance(modos[0]);
                cipher.init(Cipher.ENCRYPT_MODE, skey);
            }

            /* If the cipher has modes, besides the secret key is also necessary
            create an Initialization Vector(IV) to start the cipher. */
            else {
                /* Tell the server the name and cipher modes. */
                dos.write((modos[0] + "/" + modos[1] + "/" + modos[2]).getBytes());

                /* Begins an IV of 16 positions in a safe way. */
                SecureRandom random = new SecureRandom();
                byte[] iv = new byte[16];
                random.nextBytes(iv);

                /* Tell to server which IV is been used. */
                dos.write(iv);

                /* Begins an IvParameterSpec with the IV intended. */
                IvParameterSpec ivspec = new IvParameterSpec(iv);

                /* Starts the cipher with modes, secret key and IV expected. */
                cipher = Cipher.getInstance(modos[0]+"/"+modos[1]+"/"+modos[2]);
                cipher.init(Cipher.ENCRYPT_MODE, skey, ivspec);
            }

            CipherOutputStream cos = new CipherOutputStream(this.socket.getOutputStream(), cipher);

            /* Send to server all the inserted messages in the terminal client. */
            int input;
            while((input = System.in.read()) !=-1) {
                cos.write((byte) input);
                cos.flush();
            }

            System.out.println("Connection Finished !");
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