package main;

import srv.Server;

/**
 * Created by paulosilva and davidbranco on 16/02/15.
 */
public class Main_server {

    /* Metod that takes 2 parameters: host and port */
    public static void main (String [] args){
        Server s = new Server(args[0],Integer.parseInt(args[1]));
        s.start();
    }
}
