package rc4;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by paulosilva and davidbranco on 19/02/15.
 */

/*
 Class which generates random secret keys, encrypts and decrypts the content of certain file.
 */
public class RC4 {

    /* Function which generates random secret keys, and after save them in an intended file */
    public static void genKey (String keyfile) throws NoSuchAlgorithmException, IOException {

        KeyGenerator kg = KeyGenerator.getInstance("RC4");
        SecretKey skey = kg.generateKey();

        byte [] key = skey.getEncoded();

        FileOutputStream fos = new FileOutputStream(keyfile);
        fos.write(key);
        fos.close();
    }

    /* Function which encrypts and decrypts the content of a certain file (depending of chosen mode) and saves the result in intended destiny file. */
    public static void operation (String mode, String keyfile, String infile, String outfile) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        /* READ KEY FILE */
        File key_file = new File(keyfile);
        byte [] key = new byte [(int)key_file.length()];

        /* READ INPUT FILE */
        byte [] input_txt = Files.readAllBytes(Paths.get(infile));

        /* START CYPHER */
        Cipher rc4 = Cipher.getInstance("RC4");
        SecretKeySpec rc4key = new SecretKeySpec(key,"RC4");

        /*CHOOSE MODE*/
        if(mode.equals("-enc")){
            rc4.init(Cipher.ENCRYPT_MODE,rc4key);
        }
        else{
            rc4.init(Cipher.DECRYPT_MODE,rc4key);
        }

        /*RUN CIPHER*/
        byte [] output_txt = rc4.update(input_txt);

        /*WRITE OUTPUT FILE*/
        Files.write(Paths.get(outfile),output_txt);
    }
}
