/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import crypto.Crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchService;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import controllers.SignInController;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

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
    //public static SecretKey sessionKey;
    private Crypto aCrypto;
    //public static Crypto aCrypto;
    private static String userName;
    private String password;
    private static final String PATH = "src/server/users/";
    private File hashMapSer = new File("src/server/hashMap.ser");
    /*
     * Hash map in which we will store real file names with hash of file names as key - value pair
     */
    private Map<String, String> fileNamesMap = new HashMap<String, String> ();
    
    public ServerThread(Socket socket) {
        try {
            this.socket = socket;
            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
            aCrypto = new Crypto();
            if(hashMapSer.exists()) {
            	fileNamesMap = deserializeFromFile(new File("src/server/hashMap.ser"));
            }
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
                    keyGenerator = KeyGenerator.getInstance("DES");
                    sessionKey = keyGenerator.generateKey();
                    byte[] sessionKeyEnc = aCrypto.AsymmetricFileEncription(sessionKey.getEncoded(), publicKey);
                    oos.writeObject(sessionKeyEnc);
                }

                if (obj instanceof String /* && aCrypto.verifyDigitalSignature(data, signature, publicKey) */) {
                    String option = aCrypto.DecryptStringAsymmetric((String) ois.readObject(), publicKey);
                    if ("login".equals(option)) {
                        userName = aCrypto.DecryptStringAsymmetric((String) ois.readObject(), publicKey);
                        password = aCrypto.DecryptStringAsymmetric((String) ois.readObject(), publicKey);
                        //login response

                        boolean login = loginCheck(userName, password);
                        if (login) {
                            oos.writeObject(loginCheck(userName, password));
                        }
                    }

                    if ("cert".equals(option)) {

                        byte[] receivedCertificate = aCrypto.SymmetricFileDecription(((byte[]) ois.readObject()), sessionKey);

                        CertificateFactory cFactory = CertificateFactory.getInstance("X.509");

                        InputStream in = new ByteArrayInputStream(receivedCertificate);

                        X509Certificate certificate = (X509Certificate) cFactory.generateCertificate(in);
                        //System.out.println(certificate.toString());
                        String cn = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                        System.out.println("CCCCCCCCNNNNNN : " + cn);
                        if (cn.equals(certificate.getSubjectX500Principal().toString().split(",")[0])) {
                            System.out.println("CCCCCCCCNNNNNN : " + cn);

                            oos.writeObject(aCrypto.EncryptStringSymmetric("true", sessionKey));
                            System.out.println("CCCCCCCCNNNNNN : " + cn);

                        } else {
                            oos.writeObject(aCrypto.EncryptStringSymmetric("false", sessionKey));
                        }
                        //cert check
                        //    oos.writeObject(checkCertificate(certificate));
                    }
                    //for new adding new file to file system
                    if ("newFile".equals(option)) {
                        changeFileWatcher(userName);
                    }
                    //for sending files to client
                    if ("download".equals(option)) {

                    }
                    //for sending list of files 
                    System.out.println("OPTION ispod certa : " + option);

                    if ("get".equals(option)) {
                        System.out.println("OPCIJA " + option);
                        String[] fileNames = getFileNames(PATH + userName);
                      //System.out.println("FILE NAME SA SERVERA : " + fileNames[0]);
                        String[] realFileNames = new String[fileNames.length];
                        for(int i = 0; i < fileNames.length; i++) {
                        	realFileNames[i] = fileNamesMap.get(fileNames[i]);
                        }
                      //  System.out.println("REAL FILE NAME DEC FROM SERVER : " + fileNamesMap.get(fileNames[0]) + " IS EMPTY MAP : " + fileNamesMap.isEmpty());
//                        String[] cFileNames = new String[fileNames.length];
//                        for (int i = 0; i < fileNames.length; i++) {
//                            cFileNames[i] = aCrypto.DecryptStringSymmetric(fileNames[i], sessionKey);
//                        }
                        //System.out.println("REAL FILE NAMES : " + realFileNames[0]);
                        if(fileNames != null  && realFileNames.length > 0 && realFileNames[0] != null) {
                        	oos.writeObject(aCrypto.EncryptStringArraySymmetric(realFileNames, sessionKey));
                        }
                        else {
                        	String[] strings = new String[] {"",""};
                        	oos.writeObject(aCrypto.EncryptStringArraySymmetric(strings, sessionKey));
                        }
                    }
                    //for editing file on server
                    if ("modify".equals(option)) {

                        // String data = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                        //  System.out.println("DATA : " + data);
                        String fileName = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                        System.out.println("FILE NAME SERVER POSLAN IS UPANEL CONTROLLERA : " + fileName);
                       // String cFileName = aCrypto.EncryptStringSymmetric(fileName, sessionKey);
                        String formatedEncFileName = aCrypto.encodeWithSHA256(fileName).replaceAll("\\/", "");
                        File f = new File("src/server/users/" + userName + "/" + formatedEncFileName);
                        
//                	   	f.mkdir();
                        if (!f.exists()) {
                            f.createNewFile();
                            System.out.println("FILE CREATED!");
                            fileNamesMap.put(formatedEncFileName, fileName);
//                            serialize(fileNamesMap.toBytes())
                            serialize(fileNamesMap);
                           // byte[] encSerializedMap = aCrypto.SymmetricFileEncryption(serializedMap, sessionKey);
                           // aCrypto.writeToFile(new File("src/server/hashMap"), serializedMap, sessionKey);
                            System.out.println("MAP VALUE FOR " + fileNamesMap.get(formatedEncFileName));
                        }
                        byte[] file = aCrypto.SymmetricFileDecription(((byte[]) ois.readObject()), sessionKey);
                        System.out.println("FILE CONTENT :  " + new String(file));
                        aCrypto.writeToFile(f, file, sessionKey);
                        changeFileWatcher(userName);
                    }
                    if ("logs".equals(option)) {
                        oos.writeObject(aCrypto.SymmetricFileEncryption(getLog(userName), sessionKey));
                    }
                    if (("content").equals(option)) {
                        String path = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                        System.out.println("PATH " + path);
                        String content = getFileContent(path);
                        oos.writeObject(aCrypto.EncryptStringSymmetric("", sessionKey));
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

    private String[] getFileNames(String path) {

        File folder = new File(path + "/");
        File[] files = folder.listFiles();
        System.out.println("PATH : " + path);
        String[] fileNames = new String[files.length];
        int j = 0;

        for (int i = 0; i < files.length; i++) {
            if (files[i].isFile()) {
                fileNames[j] = files[i].getName();
                j++;
            }
        }
        return fileNames;
    }

    /* 
	 * Method for tracking changes on user files, and for log creation
	 *
	 **/
    private void changeFileWatcher(String uName) {

        Path path = Paths.get("src/server/users/");
        try {
            File logs = new File("src/server/Logs" + uName + "Log");
            //BufferedWriter bw = new BufferedWriter(new FileWriter(logs, true));
            if (!logs.exists()) {
                logs.createNewFile();
            }
            WatchService watcher = path.getFileSystem().newWatchService();
            path.register(watcher, StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);

            WatchKey key = watcher.take();

            List<WatchEvent<?>> events = key.pollEvents();
            byte[] text = null;
            for (WatchEvent event : events) {
                if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                    text = ("\n" + LocalDateTime.now() + " user " + uName + " " + event.context()).toString().getBytes("UTF8");

//					bw.append(" ");
//					bw.append(LocalDateTime.now() + " user " + uName + " " + event.context().toString());
                }
                if (event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {
//					bw.append(" ");
                    //		bw.append(LocalDateTime.now() + " user " + uName + " " + event.context().toString());
                    text = (LocalDateTime.now() + " user " + uName + " " + event.context()).toString().getBytes("UTF8");

                }
                if (event.kind() == StandardWatchEventKinds.ENTRY_DELETE) {
//					bw.append(" ");
                    text = (LocalDateTime.now() + " user " + uName + " " + event.context()).toString().getBytes("UTF8");
                }

                aCrypto.writeToFile(logs, text, sessionKey);
//				byte[] bytesLogsEnc = aCrypto.SymmetricFileEncryption(text, sessionKey);
//				
//				BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(logs, true));
//			    
//				bufferedOutputStream.write(bytesLogsEnc);
//			    bufferedOutputStream.flush();
//			    bufferedOutputStream.close();

//				BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(logs));
//			    bufferedInputStream.read(bytesLogs);
//			    bufferedInputStream.close();
                //aCrypto.SymmetricFileEncryption(logs, sessionKey);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] getLog(String uName) throws IOException {

        File f = new File("src/server/" + uName + "Logs");
        if (!f.exists()) {
            f.createNewFile();
        }
        byte[] file = new byte[(int) f.length()];
        FileInputStream fin = new FileInputStream(f);

        fin.read(file);
        try {
            byte[] fileDec = aCrypto.SymmetricFileDecription(file, sessionKey);

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            fin.close();
        }
        return file;
    }

    public static String getUserName() {
        return userName;
    }

    private boolean makeNewFile(String path, String data) throws IOException, GeneralSecurityException,
            IllegalBlockSizeException, BadPaddingException {

        boolean isCreated = false;

        File file = new File(aCrypto.EncryptStringSymmetric(path, sessionKey));
        if (!file.exists()) {
            file.createNewFile();
            aCrypto.writeToFile(file, data.getBytes(), sessionKey);
            isCreated = true;
//			BufferedWriter bw = new BufferedWriter(new FileWriter(file, false));

            //bw.append(" ");
//			bw.write(data);
//			bw.close();
        }

        return isCreated;
    }

    private String getFileContent(String pathToFile) throws IOException {

        StringBuilder sb = new StringBuilder();
        String line;
        String content = "";
        File file = new File(pathToFile);
//	BufferedReader br = new BufferedReader(new FileReader(file));
//		while((line = br.readLine()) != null) {
//			sb.append(line);
//	        sb.append(System.lineSeparator());
//		}
        try {
            FileInputStream fin = null;
            // create FileInputStream object
            fin = new FileInputStream(file);

            byte fileContent[] = new byte[(int) file.length()];

            // Reads up to certain bytes of data from this input stream into an array of bytes.
            fin.read(fileContent);
            //create string from byte array
            byte[] array = aCrypto.SymmetricFileDecription(fileContent, sessionKey);
            String s = new String(array);
            System.out.println("File content: " + s);

           // content = aCrypto.DecryptStringSymmetric(s, sessionKey);
           content += s;
            System.out.println("CONTENT : " + content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        //br.close();
        return content;
    }
    //helper method to convert Object to byte array

    private  void serialize(Object obj) throws IOException {
    	File f = new File("src/server/hashMap.ser");
    	if(!f.exists()) {
    		f.createNewFile();
    	}
    	FileOutputStream fos = new FileOutputStream(f);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(obj);
        oos.close();
        fos.close();
    }

    private  Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream b = new ByteArrayInputStream(bytes)) {
            try (ObjectInputStream o = new ObjectInputStream(b)) {
                return o.readObject();
            }
        }
    }
    private HashMap<String, String> deserializeFromFile(File f) {
		
    	Map<String, String> map = new HashMap<String, String>();
    	
    	try {
             FileInputStream fis = new FileInputStream(f);
             ObjectInputStream ois = new ObjectInputStream(fis);
             map = (HashMap<String,String>) ois.readObject();
             
             ois.close();
             fis.close();
          } catch(IOException ioe) {
             ioe.printStackTrace();
          } catch(ClassNotFoundException c) {
             System.out.println("Class not found");
             c.printStackTrace();
          }
    	  return (HashMap<String, String>) map;
    }
}
