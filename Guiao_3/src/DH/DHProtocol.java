package DH;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by paulosilva and davidbranco on 03/03/15.
 */
public class DHProtocol {

    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }

    public static void main (String [] args) throws Exception {

        /* Primeiro Elemento: Alice
           Segundo Elemento: Bob
         */


        /* Criar os parametros Diffie Hellman */
        System.out.println ("Creating Diffie-Hellman parameters (takes VERY long) ...");
        
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        paramGen.generateParameters();
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhps = params.getParameterSpec(DHParameterSpec.class);


        /* Alice cria o seu par de chaves */
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(dhps);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();


        /* Alice cria e inicializa o seu objecto para o acordo de chaves DH */
        System.out.println("ALICE: Initialization ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        /* Alice codifica a sua chave publica para enviar ao Bob*/
        byte [] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();


        /* Bob recebe a chave da Alice codificada, e faz a respectiva conversão */
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

        /* Bob obtem os parametros DH associados à chave da Alice */
        DHParameterSpec dhps2 = ((DHPublicKey) alicePubKey).getParams();

        /* Bob cria o seu par de chaves */
        System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhps2);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();


        /* Bob cria e inicializa o seu objecto para o acordo de chaves DH */
        System.out.println("BOB: Initialization ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());


        /* Bob codifica a sua chave publica para enviar à Alice*/
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();


        /* Alice recebe a chave do Bob codificada, e faz a respectiva conversão */
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);


        /* Alice utiliza a chave publica do Bob e finaliza o protocolo */
        System.out.println("ALICE: Key Agree");
        aliceKeyAgree.doPhase(bobPubKey,true);

        /* Bob utiliza a chave publica da Alice e finaliza o protocolo */
        System.out.println("Bob: Key Agree");
        bobKeyAgree.doPhase(alicePubKey,true);


        /* Verificar se ambos tem a mesma chave */
        byte [] aliceKey = aliceKeyAgree.generateSecret();
        byte [] bobKey = new byte[aliceKey.length];

        bobKeyAgree.generateSecret(bobKey, 0);

        if (!java.util.Arrays.equals(aliceKey, bobKey))
            throw new Exception("Shared secrets differ");

        System.out.println("Shared secrets are the same !!");
        System.out.println("Alice: " + toHexString(aliceKey));
        System.out.println("Bob  : " + toHexString(bobKey));
    }
}