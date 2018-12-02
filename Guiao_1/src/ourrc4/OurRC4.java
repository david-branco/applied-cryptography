package ourrc4;

/**
 * Created by paulosilva and davidbranco on 21-02-2015.
 */

/*
   Class with a possible implementation of RC4
   Uses algorithms based on those described in wikipedia and slides of the discipline.
   Benefits from the well known properties of integers and characters for a more easier management of their arrays,
 */
   
public class OurRC4 {

    private char[] S = new char[256];
    private char[] K = new char[256];
    private int keySize;

    /* Function that returns the positive module */
    private int myMod(int x, int modulo) {
        return ((x % modulo) + modulo)  % modulo;
    }

    public OurRC4(byte[] key) throws Exception {
        this.keySize = key.length;

        if (keySize < 1 || keySize > 256)
            throw new Exception("Key size must between 1 and 256 bytes");

        /* Initialize SandBox and set Key */
        for (int i = 0; i < 256; i++) {
            S[i] = (char) i;
            K[i] = (char) key[myMod(i, keySize)];
        }

        for(int i = 0, j = 0; i < 256; i++) {
            j = myMod(j + S[i] + K[i], 256);
            /* Swap with exclusive OR */
            S[i] ^= S[j];
            S[j] ^= S[i];
            S[i] ^= S[j];
        }
    }

    /* Encrypt or Decrypt text*/
    public char[] operation(char[] input_text) {
        char[] output_text = new char[input_text.length];
        int i = 0, j= 0, k, t;

        for(int c = 0; c < input_text.length; c++) {
            i = myMod(i + 1, 256);
            j = myMod(j + S[i], 256);

            /* Swap with exclusive OR */
            S[i] ^= S[j];
            S[j] ^= S[i];
            S[i] ^= S[j];

            t = myMod(S[i] + S[j], 256);
            k = S[t];
            output_text[c] = (char) (input_text[c] ^ k);
        }
        return output_text;
    }
}
