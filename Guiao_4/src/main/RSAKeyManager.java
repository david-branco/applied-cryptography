package main;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Created by db on 22-05-2015.
 */
public class RSAKeyManager {

    final static String SERVER_PRIVATE_KEY_FILE = "keys/server_private.key";
    final static String SERVER_PUBLIC_KEY_FILE = "keys/server_public.key";

    final static String CLIENT_PRIVATE_KEY_FILE = "keys/client_private.key";
    final static String CLIENT_PUBLIC_KEY_FILE = "keys/client_public.key";

    public static void generateKey(int keysize) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keysize);
        KeyPair key = keyGen.generateKeyPair();

        /* Server Keys */
        File serverPrivateKeyFile = new File(SERVER_PRIVATE_KEY_FILE);
        File serverPublicKeyFile = new File(SERVER_PUBLIC_KEY_FILE);

        if (serverPrivateKeyFile.getParent() != null)
            serverPrivateKeyFile.getParentFile().mkdir();
        serverPrivateKeyFile.createNewFile();

        if (serverPublicKeyFile.getParent() != null)
            serverPublicKeyFile.getParentFile().mkdir();
        serverPublicKeyFile.createNewFile();

        ObjectOutputStream serverPublicKeyOS = new ObjectOutputStream(new FileOutputStream(serverPublicKeyFile));
        serverPublicKeyOS.writeObject(key.getPublic());
        serverPublicKeyOS.close();

        ObjectOutputStream serverPrivateKeyOS = new ObjectOutputStream(new FileOutputStream(serverPrivateKeyFile));
        serverPrivateKeyOS.writeObject(key.getPrivate());
        serverPrivateKeyOS.close();

        /* Client Keys */
        File clientPrivateKeyFile = new File(CLIENT_PRIVATE_KEY_FILE);
        File clientPublicKeyFile = new File(CLIENT_PUBLIC_KEY_FILE);

        if (clientPrivateKeyFile.getParent() != null)
            clientPrivateKeyFile.getParentFile().mkdir();
        clientPrivateKeyFile.createNewFile();

        if (clientPublicKeyFile.getParent() != null)
            clientPublicKeyFile.getParentFile().mkdir();
        clientPublicKeyFile.createNewFile();

        ObjectOutputStream clientPublicKeyOS = new ObjectOutputStream(new FileOutputStream(clientPublicKeyFile));
        clientPublicKeyOS.writeObject(key.getPublic());
        clientPublicKeyOS.close();

        ObjectOutputStream clientPrivateKeyOS = new ObjectOutputStream(new FileOutputStream(clientPrivateKeyFile));
        clientPrivateKeyOS.writeObject(key.getPrivate());
        clientPrivateKeyOS.close();
    }


    public static void main(String args[]) throws NoSuchAlgorithmException, IOException {
        generateKey(1024);
        System.out.println("Keys generated with success !!");
    }
}
