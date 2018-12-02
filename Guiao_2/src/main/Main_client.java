package main;

import srv.Client;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */
public class Main_client {

    /* Method that takes as parameters: host, port, the cipher name and mods (if exist)*/
    public static void main (String [] args){
        Client c;

        if(args.length == 3) {
            c = new Client(args[0], Integer.parseInt(args[1]), new String[] {args[2]} );
        }
        else {
            c = new Client(args[0], Integer.parseInt(args[1]), new String[] {args[2], args[3], args[4]} );
        }
        c.start();
    }
}
