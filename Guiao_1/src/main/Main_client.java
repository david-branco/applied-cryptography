package main;

import srv.Client;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */
public class Main_client {

		/* Metod that takes 2 parameters: host and port */
    public static void main (String [] args){
        Client c = new Client(args[0],Integer.parseInt(args[1]));
        c.start();
    }
}
