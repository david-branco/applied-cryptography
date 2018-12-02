package srv;

import main.ValidateCertPath;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */

/* Thread which will manage the Client and Server interaction after the connection between them */
public class Point extends Thread {

    private final Socket socket;
    private int id;

    private String modo;
    private Cipher decCipher;
    private Cipher encCipher;

    private byte[] keyMac;
    private byte[] agreedKey;
    private byte[] cKey;
    private byte[] mKey;
    private byte [] clientPubKeyEnc;
    private byte [] serverPubKeyEnc;
    private Mac mac;

    private IvParameterSpec ivspec;
    private CipherInputStream cis;

    private DataInputStream dis;
    private DataOutputStream dos;

    private String PRIVATE_KEY_FILE = "keys/server_private.key";
    private String PUBLIC_KEY_FILE = "keys/server_public.key";

    private String CA_CERT = "certs/cacert.pem";
    private String SERVER_CERT = "certs/server_cert.pem";
    private String SERVER_KEY = "certs/server_key.pk8";
    private String CLIENT_CERT = "certs/client_cert_received.pem";

    public Point(int id, Socket socket){
        this.id = id;
        this.socket = socket;

        try {
            this.dis = new DataInputStream(this.socket.getInputStream());
            this.dos = new DataOutputStream(this.socket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void start_key_exchange() throws Exception {

        /* Creating the Diffie Hellman parameters */
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        paramGen.generateParameters();

        /* DH parameters option 1: always random -- very slow */
        //AlgorithmParameters params = paramGen.generateParameters();

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

        /* Receives the coded key */
        int clientPubKeyEncSize = this.dis.readInt();
        clientPubKeyEnc = new byte[clientPubKeyEncSize];
        this.dis.readFully(clientPubKeyEnc, 0, clientPubKeyEncSize);

        KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);
        PublicKey clientPubKey = clientKeyFac.generatePublic(x509KeySpec);

        /* Creating key pair */
        //DHParameterSpec dhps = ((DHPublicKey) clientPubKey).getParams();
        KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
        serverKpairGen.initialize(dhps);
        KeyPair serverKpair = serverKpairGen.generateKeyPair();

        /* Creating KeyAgreement for DH */
        KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
        serverKeyAgree.init(serverKpair.getPrivate());

        /* Codes public key for the Public */
        serverPubKeyEnc = serverKpair.getPublic().getEncoded();
        this.dos.writeInt(serverPubKeyEnc.length);
        this.dos.write(serverPubKeyEnc);
        this.dos.flush();

        /* Using the server public key and finalizes the protocol */
        serverKeyAgree.doPhase(clientPubKey, true);
        this.agreedKey = serverKeyAgree.generateSecret();
        this.cKey = Arrays.copyOfRange(agreedKey, 0, agreedKey.length / 2);
        this.mKey = Arrays.copyOfRange(agreedKey, agreedKey.length / 2, agreedKey.length);
    }

    private void start_digest() throws InvalidKeyException, NoSuchAlgorithmException {

        /* Init MAC process */
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(mKey);
        this.keyMac = digest.digest();
        this.mac = Mac.getInstance("HmacSHA256");
    }

    private void start_cipher() throws IOException {

        try {
            /* Reading the name and cipher modes (if any) intended by the client. */
            int size = this.dis.readInt();
            byte[] modoClient = new byte[size];
            dis.read(modoClient);
            this.modo = new String(modoClient);

            /* Creation of a SecretKeySpec with the cipher name. */
            String[] modos = this.modo.split("/");
            //SecretKeySpec sKey = new SecretKeySpec("SDCSSI20142015".getBytes(), modos[0]);
            SecretKeySpec sKey = new SecretKeySpec(this.cKey, modos[0]);
            this.mac.init(new SecretKeySpec(this.keyMac, modos[0]));

            /* Case the client intends a cipher with modes, is also read the desired Initialization Vector(IV). */
            if (modos.length > 1) {
                byte[] iv = new byte[16];
                dis.read(iv);
                ivspec = new IvParameterSpec(iv);
            }

            /* Initialization of cipher with the obtained values. */
            decCipher = Cipher.getInstance(modo);
            encCipher = Cipher.getInstance(modo);
            if (modos.length == 1) {
                decCipher.init(Cipher.DECRYPT_MODE, sKey);
                encCipher.init(Cipher.ENCRYPT_MODE, sKey);
            } else {
                decCipher.init(Cipher.DECRYPT_MODE, sKey, ivspec);
                encCipher.init(Cipher.ENCRYPT_MODE, sKey, ivspec);
            }

            this.cis = new CipherInputStream(this.socket.getInputStream(), decCipher);

        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    private void start_signature_exchange() throws Exception {

        /* Read RSA Keys from file */
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
        PrivateKey privateRSAKey = (PrivateKey) ois.readObject();

        ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
        PublicKey publicRSAKey = (PublicKey) ois.readObject();

        /* Sign and Encrypt the public keys */
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateRSAKey);
        sig.update(clientPubKeyEnc);
        sig.update(serverPubKeyEnc);
        byte[] serverEncryptedSignature = encCipher.doFinal(sig.sign());

        /* Send Encrypted Signature to Client */
        this.dos.writeInt(serverEncryptedSignature.length);
        this.dos.write(serverEncryptedSignature);
        this.dos.flush();

        /* Receives Encrypted Signature from Client */
        int clientEncryptedSignatureSize = this.dis.readInt();
        byte[] clientEncryptedSignature = new byte[clientEncryptedSignatureSize];
        this.dis.readFully(clientEncryptedSignature, 0, clientEncryptedSignatureSize);

        /* Decrypt and Verify received signature */
        byte[] clientSignature = decCipher.doFinal(clientEncryptedSignature);
        sig.initVerify(publicRSAKey);
        sig.update(clientPubKeyEnc);
        sig.update(serverPubKeyEnc);
        if (!sig.verify(clientSignature)) {
            throw new Exception("Signature differ");
        }
    }

    private void start_certificate() throws Exception {

        /* Read Certificate from file */
        X509Certificate serverCertificate = ValidateCertPath.getCertFromFile(SERVER_CERT);
        byte[] serverCertificateEnc = serverCertificate.getEncoded();

        /* Send Certificate to Client */
        this.dos.writeInt(serverCertificateEnc.length);
        this.dos.write(serverCertificateEnc);
        this.dos.flush();

        /* Receive Certificate from Client */
        int clientCertificateEncSize = this.dis.readInt();
        byte[] clientCertificateEnc = new byte[clientCertificateEncSize];
        this.dis.readFully(clientCertificateEnc, 0, clientCertificateEncSize);

        Certificate clientCertificate =
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(clientCertificateEnc));

        /* Save Client Certificate */
        PrintWriter pw = new PrintWriter(new FileWriter(CLIENT_CERT));
        pw.println("-----BEGIN CERTIFICATE-----");
        pw.println(DatatypeConverter.printBase64Binary(clientCertificateEnc));
        pw.println("-----END CERTIFICATE-----");
        pw.close();

        /* Validate Client Certificate */
        ValidateCertPath vcp = new ValidateCertPath();
        vcp.validateCertPath(new String[]{CA_CERT, CLIENT_CERT});

        /* Read RSA Private Key */
        Path key_path = Paths.get(SERVER_KEY);
        byte[] encodedKey = Files.readAllBytes(key_path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateRSAKey = (RSAPrivateKey)keyFactory.generatePrivate(keySpec);

        /* Sign and Encrypt the public keys */
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateRSAKey);
        sig.update(clientPubKeyEnc);
        sig.update(serverPubKeyEnc);
        byte[] serverEncryptedSignature = encCipher.doFinal(sig.sign());

        /* Send Encrypted Signature to Client */
        this.dos.writeInt(serverEncryptedSignature.length);
        this.dos.write(serverEncryptedSignature);
        this.dos.flush();

        /* Receives Encrypted Signature from Client */
        int clientEncryptedSignatureSize = this.dis.readInt();
        byte[] clientEncryptedSignature = new byte[clientEncryptedSignatureSize];
        this.dis.readFully(clientEncryptedSignature, 0, clientEncryptedSignatureSize);

        /* Decrypt and Verify received signature */
        byte[] clientSignature = decCipher.doFinal(clientEncryptedSignature);
        sig.initVerify(clientCertificate.getPublicKey());
        sig.update(clientPubKeyEnc);
        sig.update(serverPubKeyEnc);
        if (!sig.verify(clientSignature)) {
            throw new Exception("Signature differ");
        }
    }

    @Override
    public void run() {
        try {
            System.out.println("(Point, Socket)" + "(" + this.id + "," + this.socket.toString() + ")");

            System.out.println("Key agreement ...");
            start_key_exchange();
            System.out.println("Key digest ...");
            start_digest();
            System.out.println("Initializing cipher ...");
            start_cipher();
            System.out.println("Signature verification ...");
            start_signature_exchange();
            //System.out.println("Verifying certificates ...");
            //start_certificate();
            System.out.println("Server is ready !");

            int messageSize;

            while ((messageSize = cis.read()) != -1) {
                byte[] message = new byte[messageSize];
                cis.read(message);

                System.out.println(this.id + ": "+ new String(message));

                byte[] digestServer = mac.doFinal(message);
                int digestSize = cis.read();
                byte[] digestClient = new byte[digestSize];
                cis.read(digestClient);
                if (!java.util.Arrays.equals(digestServer, digestClient))
                    throw new Exception("Digest differ");
            }

            System.out.println("Client " + this.id + " disconnected !");
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

