/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import crypto.Crypto;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;

/**
 *
 * @author Milan
 */
public class ServerThread extends Thread {

    private Socket socket;
    private ObjectOutputStream oos;
    private ObjectInputStream ois;
    private PublicKey publicKey;
    private KeyGenerator keyGenerator;
    private SecretKey sessionKey;
    private Crypto aCrypto;
    private String userName;
    private String password;

    public ServerThread(Socket socket) {
        try {
            this.socket = socket;
            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
            aCrypto = new Crypto();
            start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void run() {
        try {
            while (true) {
                Object obj = ois.readObject();
                if (obj instanceof PublicKey) {
                    publicKey = (PublicKey) obj;
                    keyGenerator = KeyGenerator.getInstance("AES");
                    sessionKey = keyGenerator.generateKey();
                    byte[] sessionKeyEnc = aCrypto.AsymmetricFileEncription(sessionKey.getEncoded(), publicKey);
                    oos.writeObject(sessionKeyEnc);
                }

                if (obj instanceof String) {
                    String option = aCrypto.DecryptStringAsymmetric((String) ois.readObject(), publicKey);
                    System.out.println("OPTION " + "cert".equals(option));
                    if ("login".equals(option)) {
                        userName = aCrypto.DecryptStringAsymmetric((String) ois.readObject(), publicKey);
                        password = aCrypto.DecryptStringAsymmetric((String) ois.readObject(), publicKey);
                        //login response
                        boolean login = loginCheck(userName, password);
                        if (login) {
                            oos.writeObject(loginCheck(userName, password));	
                        }
                    }
                    
                   if("cert".equals(option)) {

                       byte[] receivedCertificate = aCrypto.SymmetricFileDecription(((byte[]) ois.readObject()), sessionKey);
                       System.out.println("CERT: " + receivedCertificate);

                       CertificateFactory cFactory = CertificateFactory.getInstance("X.509");
                       System.out.println("MILAN");

                       InputStream in = new ByteArrayInputStream(receivedCertificate);
                       System.out.println("MILAN");

                       X509Certificate certificate = (X509Certificate) cFactory.generateCertificate(in);
                       System.out.println("CERT FINAL : " + certificate);
                     //  oos.writeObject("true");
                       //cert check
                   //    oos.writeObject(checkCertificate(certificate));
                   }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //helper method for checking credentials
    private boolean loginCheck(String userName, String password) {
        boolean login = false;
        String line = null;
        try {
            File f = new File("src/server/users.txt");
            BufferedReader br = new BufferedReader(new FileReader(f));
            while ((line = br.readLine()) != null) {
                String uName = line.split("#")[0];
                String pass = line.split("#")[1];

                if (userName.equals(uName) && password.equals(pass)) {
                   
                    login = true;

                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return login;
    }

    //helper method for checking is certificate active in crl
    public boolean checkCertificate(X509Certificate certificate) {
        boolean active = false;

        return active;
    }
}
