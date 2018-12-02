package main;

import rc4.RC4;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static java.lang.System.out;

/**
 * Created by paulosilva and davidbranco on 19/02/15.
 */

/* Class that will interact with RC4 class, according to the received arguments on terminal.
   User is notified in case of the arguments are not the desired.

    Examples of correct utilization:
    prog -genkey <keyfile>
    prog -enc <keyfile> <infile> <outfile>
    prog -dec <keyfile> <infile> <outfile>
* */

public class Main_rc4 {
    public static void main (String [] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {

        switch (args[0]){
            case "-genkey" :
                if (args.length == 2 ){
                    RC4.genKey(args[1]);
                    out.println ("key file generated to " + args[1]);
                }
                else{
                    out.println ("invalid number of arguments");
                }
                 break;

            case "-enc" :
            case "-dec" :
                if(args.length == 4) {
                    RC4.operation(args[0],args[1],args[2],args[3]);
                    out.println("file " + args[2] + " " + args[0].substring(1) + "rypted to file " + args[3] + " with key in " + args[1]);
                }
                else{
                    out.println ("invalid number of arguments");
                }
                break;

            default : out.println ("Command not found");
        }
    }
}
