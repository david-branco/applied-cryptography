package main;

import ourrc4.OurRC4;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Created by paulosilva and davidbranco on 21-02-2015.
 */

public class Main_OurRC4 {

    public static void main(String[] args) throws Exception {

        /* Generate random secret key */
        KeyGenerator kg = KeyGenerator.getInstance("RC4");
        SecretKey skey = kg.generateKey();
        byte[] key = skey.getEncoded();

        /* Initialize the ciphers */
        OurRC4 rc4Enc = new OurRC4(key);
        OurRC4 rc4Dec = new OurRC4(key);

        /* Text to manage */
        String text = "Ola Mundo !";
        System.out.println(text);

        /* Encrypt and show the result */
        char[] encrypt = rc4Enc.operation((text.toCharArray()));
        System.out.println(encrypt);

        /* Decrypt and show the result */
        char[] decrypt = rc4Dec.operation(encrypt);
        System.out.println(decrypt);
    }
}