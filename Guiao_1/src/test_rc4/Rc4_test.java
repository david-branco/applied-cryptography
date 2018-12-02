package test_rc4;

import main.Main_rc4;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by paulosilva and davidbranco on 19/02/15.
 */

/*
 Test class to RC4 class where:
 - Generates files with clean content, secret keys, encrypts content and decrypts content (each type of file in a
   different folder, all of them inside the files_test folder.
 - At last, verifies if the content of clean file and decrypted file is the same.
 */
public class Rc4_test {

    /* Auxiliary function that compares if 2 files has the same content */
    public static boolean comp_files (String file1, String file2) throws IOException {

        BufferedReader br1 = new BufferedReader(new InputStreamReader(new DataInputStream(new FileInputStream(file1))));
        BufferedReader br2 = new BufferedReader(new InputStreamReader(new DataInputStream(new FileInputStream(file2))));

        String str1, str2;
        while((str1 = br1.readLine()) != null && (str2 = br2.readLine()) !=null){
            if(!str1.equals(str2)){
                return false;
            }
        }

        return true;
    }


    public static void main (String args[]) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        /* Array of Strings containing the desired content for the files with clean text. */
        String cleans[] = {
            "Counter-terror police issue appeal for information about three girls aged between 15 and 16 who left their homes in east London last week and caught a flight to Turkey",
            "Three teenage girls are feared to be on their way to join Islamic State militants in Syria after fleeing their London homes in the school half-term holidays.",
            "The girls – named as Shamima Begum, 15, Kadiza Sultana, 16, and an unidentified 15-year-old girl – slipped out of their homes in east London last Tuesday and secretly caught a flight to Istanbul, Turkey.",
            "The three girls, all academically-gifted students at Bethnal Green academy in east London, were friends with a 15-year-old girl who is believed to have travelled to join Islamic State (Isis) last December.",
            "The three girls were interviewed in December by detectives about the whereabouts of their friend but were not themselves considered at risk of fleeing Britain. There are now concerns that the girls may be planning to meet up with their friend in Isis-held territory."
        };

        /* Cycle that creates the necessary and described files, in the respective folders */
        for(int i = 0; i< cleans.length;  i++){

            /* Create clean files */
            Files.write(Paths.get("files_test/clean/clean" + i + ".txt"), cleans[i].getBytes());

            /* Create keys */
            Main_rc4.main(new String[]{"-genkey", "files_test/keys/key"+i+".bin"});

            /*Create encrypted files*/
            Main_rc4.main(new String[]{"-enc", "files_test/keys/key"+i+".bin","files_test/clean/clean" + i + ".txt", "files_test/encrypted/encrypted" + i +".txt"});

            /*Create decrypted files */
            Main_rc4.main(new String[]{"-dec", "files_test/keys/key"+i+".bin","files_test/encrypted/encrypted" + i +".txt", "files_test/decrypted/decrypted" + i + ".txt"});
        }


        /* Comparison of content from the files with clean and deciphered text. */
        for (int i = 0; i< cleans.length; i++){
            boolean comp = comp_files("files_test/clean/clean" + i + ".txt","files_test/decrypted/decrypted" + i + ".txt");
            System.out.println ("clean" + i + " is equal to decrypted" + i + " ? " + comp);
        }
    }

}

