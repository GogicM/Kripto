/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import crypto.Crypto;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchService;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import javax.crypto.spec.SecretKeySpec;

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
    private SecretKey serverSecretKey;
    //public static SecretKey sessionKey;
    private Crypto aCrypto;
    //public static Crypto aCrypto;
    private static String userName;
    private String password;
    private String[] fileNames;
    private static final String PATH = "src/server/users/";
    private File hashMapSer = new File("src/server/hashMap.ser");
    /*
     * Hash map in which we will store real file names with hash of file names as key - value pair
     */
    private Map<String, String> fileNamesMap = new HashMap<String, String>();
    /*
     * Hash map in which we will store real file names with file content for sending user
     */
    private Map<String, String> filesForUserMap = new HashMap<String, String>();
    private String fileName = null;
    private PrivateKey privateKey;

    public ServerThread(Socket socket) {
        try {
            this.socket = socket;
            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
            aCrypto = new Crypto();
            if (hashMapSer.exists()) {
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
                    keyGenerator = KeyGenerator.getInstance("AES");
                    keyGenerator.init(128);
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
                        privateKey = aCrypto.getPrivateKey("src/keys/" + userName + "DER.key");
                        File keyFile = new File("src/server/serverSessionKey" + userName);
                        keyFile.setReadOnly();
                        if (!keyFile.exists()) {
                            serverSecretKey = keyGenerator.generateKey();
                            writeKeyToFile(keyFile, serverSecretKey);
                        } else {
                            serverSecretKey = readKeyFromFile(keyFile, privateKey);
                        }

                    }
                    setUserName(userName);
                    if ("cert".equals(option)) {

                        byte[] receivedCertificate = aCrypto.SymmetricFileDecription(((byte[]) ois.readObject()), sessionKey);

                        CertificateFactory cFactory = CertificateFactory.getInstance("X.509");

                        InputStream in = new ByteArrayInputStream(receivedCertificate);

                        X509Certificate certificate = (X509Certificate) cFactory.generateCertificate(in);
                        //System.out.println(certificate.toString());
                        String cn = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
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
                  
                    //for sending list of files 
                    if ("get".equals(option)) {
                        fileNames = getFileNames(PATH + userName);
                        String[] realFileNames = new String[fileNames.length];
                        for (int i = 0; i < fileNames.length; i++) {
                            realFileNames[i] = fileNamesMap.get(fileNames[i]);
                        }
//                        System.out.println("REAL FILE NAMES : " + realFileNames[0]);
                        if (fileNames != null && realFileNames.length > 0 && realFileNames[0] != null) {
                            oos.writeObject(aCrypto.EncryptStringArraySymmetric(realFileNames, sessionKey));
                        } else {
                            String[] strings = new String[]{"", ""};
                            oos.writeObject(aCrypto.EncryptStringArraySymmetric(strings, sessionKey));
                        }
                    }
                    //for adding new file on server
                    if ("new".equals(option)) {
                        String fileName = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                        System.out.println("FILE NAME SERVER POSLAN IS UPANEL CONTROLLERA : " + fileName);
                        // String cFileName = aCrypto.EncryptStringSymmetric(fileName, sessionKey);
                        String formatedEncFileName = aCrypto.encodeWithSHA256(fileName).replaceAll("\\/", "");
                        File f = new File("src/server/users/" + userName + "/" + formatedEncFileName);

                        if (!f.exists()) {
                            f.createNewFile();
                            System.out.println("FILE CREATED!");
                            fileNamesMap.put(formatedEncFileName, fileName);
                            serialize(fileNamesMap, "src/server/hashMap.ser");
                            System.out.println("MAP VALUE FOR " + fileNamesMap.get(formatedEncFileName));
                        }
                        byte[] file = aCrypto.SymmetricFileDecription(((byte[]) ois.readObject()), sessionKey);
                        System.out.println("FILE CONTENT :  " + new String(file));
                        String s = new String(file);
                        // String encContent = aCrypto.EncryptStringSymmetric(new String(file), sessionKey);
                        aCrypto.writeToFile(f, s.getBytes(), serverSecretKey);
                        oos.writeObject(aCrypto.EncryptStringSymmetric(((f.exists()) ? "true" : "false"), sessionKey));
                    }
                    if ("logs".equals(option)) {
                        oos.writeObject(aCrypto.SymmetricFileEncryption(getLog(userName, serverSecretKey), sessionKey));
                    }
                    if (("content").equals(option)) {
                        String path = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                        System.out.println("PATH " + path);
                        String content = getFileContent(path);
                        oos.writeObject(aCrypto.EncryptStringSymmetric("", sessionKey));
                    }
                    if (("edit").equals(option)) {
                        fileName = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                        byte[] content = aCrypto.readFromFile(new File(PATH + userName + "/" + (String) getKeyFromValue(fileNamesMap, fileName.split("/")[4])), serverSecretKey);
                       // String fileContent = aCrypto.DecryptStringSymmetric(new String(content), sessionKey);
                       String fileContent = new String(content); 
                       oos.writeObject(aCrypto.EncryptStringSymmetric(fileContent, sessionKey));
                    }
                    if (("modify").equals(option)) {
                        String editedFileContent = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                        //String encrytedFileContent = aCrypto.EncryptStringSymmetric(editedFileContent, sessionKey);
                        File f = new File(PATH + userName + "/" + (String) getKeyFromValue(fileNamesMap, fileName.split("/")[4]));
                        aCrypto.writeToFile(f, editedFileContent.getBytes(), serverSecretKey);
                        changeFileWatcher(userName);
                        
                        oos.writeObject(aCrypto.EncryptStringSymmetric("true", sessionKey));
                    }
                    //for sending files to client
                    if(("download").equals(option)) {
                        for(int i = 0; i < fileNames.length; i++) {
                            //Adding file name and file content to map
                            String fileContentForUser = new String(aCrypto.readFromFile(new File(PATH + userName + "/" + fileNames[i]), serverSecretKey));
                            String fileNameWithContent = fileNamesMap.get(fileNames[i]) + "#" + fileContentForUser;
                            /* 
                             * In file names map as a key we are using real file name , and as a value we are using file content
                             */
//                            System.out.println("KLJUC : " + fileNamesMap.get(fileNames[i]));
//                            fileNamesMap.put(fileNamesMap.get(fileNames[i]), fileContentForUser);
                            System.out.println("FILE NAME I FILE CONTENT : " + fileNameWithContent);
                          //  byte[] byteMap = hashMapToByteArray((HashMap<String, String>) fileNamesMap);
                            oos.writeObject(aCrypto.EncryptStringSymmetric(fileNameWithContent, sessionKey));
                        }
                        oos.writeObject(aCrypto.EncryptStringSymmetric("stop", sessionKey));
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
     */
    private void changeFileWatcher(String uName) {

        Path path = Paths.get("src/server/users/");
        try {
            File logs = new File("src/server/logs/" + uName + "Log");
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
                }
                if (event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {
                    text = (LocalDateTime.now() + " user " + uName + " " + event.context()).toString().getBytes("UTF8");
                }
                if (event.kind() == StandardWatchEventKinds.ENTRY_DELETE) {
                    text = (LocalDateTime.now() + " user " + uName + " " + event.context()).toString().getBytes("UTF8");
                }

                aCrypto.writeToFile(logs, text, serverSecretKey);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] getLog(String uName, SecretKey key) throws IOException {

        File f = new File("src/server/logs/" + uName + "Logs");
        if (!f.exists()) {
            f.createNewFile();
        }
        byte[] file = new byte[(int) f.length()];
        FileInputStream fin = new FileInputStream(f);

        fin.read(file);
        try {
            byte[] fileDec = aCrypto.SymmetricFileDecription(file, key);

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
    public static void setUserName(String uName) {
    	userName = uName;
    }

    private boolean makeNewFile(String path, String data) throws IOException, GeneralSecurityException,
            IllegalBlockSizeException, BadPaddingException {

        boolean isCreated = false;

        File file = new File(aCrypto.EncryptStringSymmetric(path, sessionKey));
        if (!file.exists()) {
            file.createNewFile();
            aCrypto.writeToFile(file, data.getBytes(), serverSecretKey);
            isCreated = true;
        }

        return isCreated;
    }

    private String getFileContent(String pathToFile) throws IOException {

        StringBuilder sb = new StringBuilder();
        String line;
        String content = "";
        File file = new File(pathToFile);
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

    private void serialize(Object obj, String path) throws IOException {
        File f = new File(path);
        if (!f.exists()) {
            f.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(f);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(obj);
        oos.close();
        fos.close();
        
    }

    private Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
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
            map = (HashMap<String, String>) ois.readObject();

            ois.close();
            fis.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        } catch (ClassNotFoundException c) {
            System.out.println("Class not found");
            c.printStackTrace();
        }
        return (HashMap<String, String>) map;
    }

    /*
    * Helper method for getting key based on value sent from controller
    * I send real file name from server, and need to find his hash value in order
    * to access it on disk
     */
    private String getKeyFromValue(Map<String, String> map, String value) {
        String key = null;
        System.out.println("VALUE : " + value);
        for (String s : map.keySet()) {
            if (value.equals(map.get(s))) {
                key = s;
                break; //breaking because its one to one map
            }
        }
        System.out.println("KEY FROM VALU: " + key);
        return key;
    }

    private void writeKeyToFile(File file, SecretKey key) throws IOException,
            BadPaddingException, InvalidKeyException,
            IllegalBlockSizeException {

        byte[] encSessionKey = aCrypto.AsymmetricFileEncription(key.getEncoded(), publicKey);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(encSessionKey);
        fos.flush();
        fos.close();
    }

    private SecretKey readKeyFromFile(File keyFile, PrivateKey privateKey)
            throws FileNotFoundException, IOException, GeneralSecurityException {

        byte[] encSessionKey = new byte[(int) keyFile.length()];
        FileInputStream fis = new FileInputStream(keyFile);
        fis.read(encSessionKey);
        fis.close();
        byte[] sessionKey = aCrypto.AsymmetricFileDecription(encSessionKey, privateKey);
        SecretKey secretKey = new SecretKeySpec(sessionKey, 0, sessionKey.length, "AES");

        return secretKey;
    }
    
    private byte[] hashMapToByteArray(HashMap<String, String> map) throws IOException {
    	
    	    	
    	ByteArrayOutputStream byteStream = new ByteArrayOutputStream(5000);
    	ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(byteStream));

    	// writes the object into a bytestream
    	oos.writeObject(map);
    	oos.close();

    	byte[] byteMap = byteStream.toByteArray();
    	
    	return byteMap;
    }
}
