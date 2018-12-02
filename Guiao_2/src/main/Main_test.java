package main;

import srv.Client;
import srv.Server;

/**
 * Created by paulosilva on 01/03/15.
 */
public class Main_test {

    public static void main (String [] args){
        /* correr um servidor*/

        Server s1 = new Server("localhost",7777);
        s1.start();

        /* correr clientes com diferentes configurações*/

        Client c1 = new Client("localhost",7777, new String[]{"RC4"});
        c1.start();

        Client c2 = new Client("localhost",7777,new String []{"AES","CBC","NoPadding"});
        c2.start();

        Client c3 = new Client("localhost",7777,new String []{"AES","CBC","PKCS5Padding"});
        c3.start();

        Client c4 = new Client("localhost",7777,new String []{"AES","CFB8","PKCS5Padding"});
        c4.start();

        Client c5 = new Client("localhost",7777,new String []{"AES","CFB8","NoPadding"});
        c5.start();

        Client c6 = new Client("localhost",7777,new String []{"AES","CFB","NoPadding"});
        c6.start();
    }
}
