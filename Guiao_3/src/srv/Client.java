package srv;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */

/* Class which exchange encrypted messages with a server. */

public class Client extends Thread {
    private final String host;
    private final int port;
    private Socket socket;

    private CipherOutputStream cos;
    private DataOutputStream dos;
    private DataInputStream dis;

    private Cipher cipher;
    private byte[] agreedKey;
    private byte[] cipherKey;
    private byte[] macKey;
    private SecretKey sKey;
    private String[] modos;
    private Mac mac;

    public Client(String host, int port, String[] modos) {
        this.host = host;
        this.port = port;
        this.modos = modos;
    }

    private void start_exchange() throws Exception {

        /* Creating the Diffie Hellman parameters */
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        paramGen.generateParameters();

        /* DH parameters option 1: always random -- very slow */
        //AlgorithmParameters params = paramGen.generateParameters();
        //DHParameterSpec dhps = params.getParameterSpec(DHParameterSpec.class);

        /* DH parameters option 2: using fixed parameters */
        BigInteger P = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259" +
                "788798151499814653951492724365471316253651463342255785311748602922458795" +
                "201382445323499931625451272600173180136123245441204133515800495917242011" +
                "863558721723303661523372572477211620144038809673692512025566673746993593" +
                "384600667047373692203583");
        BigInteger G = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076" +
                "416463147265401084491113667624054557335394761604876882446924929840681990" +
                "106974314935015501571333024773172440352475358750668213444607353872754650" +
                "805031912866692119819377041901642732455911509867728218394542745330014071" +
                "040326856846990119719675");
        DHParameterSpec dhps = new DHParameterSpec(P, G);

        /* Creating key pair */
        KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
        clientKpairGen.initialize(dhps);
        KeyPair clientKpair = clientKpairGen.generateKeyPair();

        /* Creating KeyAgreement for DH */
        KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
        clientKeyAgree.init(clientKpair.getPrivate());

        /* Codes public key for the Server */
        byte [] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
        this.dos.writeInt(clientPubKeyEnc.length);
        this.dos.write(clientPubKeyEnc);
        this.dos.flush();

        /* Receives the Server key */
        int size = this.dis.readInt();
        byte [] serverPubKeyEnc = new byte[size];
        this.dis.readFully(serverPubKeyEnc, 0, size);

        KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
        PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);

        /* Using the server public key and finalizes the protocol */
        clientKeyAgree.doPhase(serverPubKey, true);
        this.agreedKey = clientKeyAgree.generateSecret();
        this.cipherKey = Arrays.copyOfRange(agreedKey, 0, agreedKey.length / 2);
        this.macKey = Arrays.copyOfRange(agreedKey, agreedKey.length / 2, agreedKey.length);

        this.sKey = new SecretKeySpec(this.cipherKey, modos[0]);
    }

    private void start_digest() throws InvalidKeyException, NoSuchAlgorithmException {

        /* Init MAC process */
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(this.macKey);
        this.mac = Mac.getInstance("HmacSHA256");
        this.mac.init(new SecretKeySpec(digest.digest(), modos[0]));
    }

    private void start_cipher() {
        try {
            /* If the used cipher in client has no modes, then it is initialized
            only with its name and secret key. */
            this.dos.writeInt(modos[0].length());
            if (modos.length == 1) {
                /* Tell the server the cipher name. */
                dos.write(modos[0].getBytes());
                cipher = Cipher.getInstance(modos[0]);
                cipher.init(Cipher.ENCRYPT_MODE, sKey);
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
                cipher = Cipher.getInstance(modos[0] + "/" + modos[1] + "/" + modos[2]);
                cipher.init(Cipher.ENCRYPT_MODE, sKey, ivspec);
            }

            this.cos = new CipherOutputStream(this.socket.getOutputStream(), cipher);

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

    @Override
    public void run() {

        /* Send to server all the inserted messages in the terminal client. */
        try {
            this.socket = new Socket(this.host, this.port);
            System.out.println("Connected with success !");

            this.dos = new DataOutputStream(socket.getOutputStream());
            this.dis = new DataInputStream(socket.getInputStream());

            System.out.println("Key agreement ...");
            start_exchange();
            System.out.println("Key digest ...");
            start_digest();
            System.out.println("Initializing cipher ...");
            start_cipher();
            System.out.println("Client is ready !");

            String message;

            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            while((message = br.readLine()) != null) {
                cos.write(message.length());
                cos.write(message.getBytes());

                byte[] digest = mac.doFinal(message.getBytes());
                cos.write(digest.length);
                cos.write(digest);
            }

            System.out.println("Connection Finished !");
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}