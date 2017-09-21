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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchService;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
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
    private static final String PATH = "src/server/users/";
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

                       CertificateFactory cFactory = CertificateFactory.getInstance("X.509");

                       InputStream in = new ByteArrayInputStream(receivedCertificate);

                       X509Certificate certificate = (X509Certificate) cFactory.generateCertificate(in);
                       //System.out.println(certificate.toString());
                       String cn = aCrypto.DecryptStringSymmetric((String) ois.readObject(), sessionKey);
                       System.out.println("CCCCCCCCNNNNNN : " + cn);
                       if(cn.equals(certificate.getSubjectX500Principal().toString().split(",")[0])) {
                           System.out.println("CCCCCCCCNNNNNN : " + cn);

                    	   oos.writeObject(aCrypto.EncryptStringSymmetric("true", sessionKey));
                           System.out.println("CCCCCCCCNNNNNN : " + cn);

                       }
                       else {
                    	   oos.writeObject(aCrypto.EncryptStringSymmetric("false", sessionKey));
                       }
                       //cert check
                   //    oos.writeObject(checkCertificate(certificate));
                   }
                   //for new adding new file to file system
                   if("newFile".equals(option)) {
                	   changeFileWatcher(userName);
                   }
                   //for sending files to client
                   if("download".equals(option)) {
                	   
                   }
                   //for sending list of files 
                   System.out.println("OPTION ispod certa : " + option);

                   if("get".equals(option)) {
                	   System.out.println("OPCIJA " + option);
                	   String[] fileNames = getFileNames(PATH + userName);
                	   String[] cFileNames = new String[fileNames.length];
                	   for(int i = 0; i < fileNames.length; i++) {
                		   cFileNames[i] = aCrypto.EncryptStringSymmetric(fileNames[i], sessionKey);
                	   }
                	   oos.writeObject(cFileNames);
                   }
                   //for editing file on server
                   if("modify".equals(option)) {
                	   
                	   File f = new File("src/server/users/" + userName);
//                	   	f.mkdir();
                	   byte[] file = aCrypto.SymmetricFileDecription(((byte[]) ois.readObject()), sessionKey);
                	   aCrypto.writeToFile(f, file, sessionKey);
                	   changeFileWatcher(userName);
                   }
                   if("logs".equals(option)) {
                	  oos.writeObject(aCrypto.SymmetricFileEncryption(getLog(userName), sessionKey)); 
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
		
		
		File folder = new File(path);
		File[] files = folder.listFiles();
		String[] fileNames = new String[files.length];
		int j = 0;
		
		for(int i = 0; i < files.length; i++) {
			if(files[i].isFile()) {
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
			File logs = new File("src/server/" + uName + "Log");
			//BufferedWriter bw = new BufferedWriter(new FileWriter(logs, true));
			
			WatchService watcher = path.getFileSystem().newWatchService();
			path.register(watcher, StandardWatchEventKinds.ENTRY_CREATE, 
					StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_DELETE);
			
			WatchKey key = watcher.take();
			
			List<WatchEvent<?>> events = key.pollEvents();
			byte[] text = null;
			for(WatchEvent event : events) {
				if(event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
		            text = ("\n" + LocalDateTime.now() + " user " + uName + " " + event.context()).toString().getBytes("UTF8");

//					bw.append(" ");
//					bw.append(LocalDateTime.now() + " user " + uName + " " + event.context().toString());
				}
				if(event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {
//					bw.append(" ");
			//		bw.append(LocalDateTime.now() + " user " + uName + " " + event.context().toString());
		            text = (LocalDateTime.now() + " user " + uName + " " + event.context()).toString().getBytes("UTF8");

				}				
				if(event.kind() == StandardWatchEventKinds.ENTRY_DELETE) {
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
			
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	
	private byte[] getLog(String uName) throws IOException {
		
		File f = new File("src/server/" + uName + "Logs");
		if(!f.exists()) {
			f.createNewFile();
		}
		byte[] file = new byte[(int) f.length()];
		FileInputStream  fin = new FileInputStream(f);
		
		fin.read(file);
		try {
			byte[] fileDec = aCrypto.SymmetricFileDecription(file, sessionKey);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		finally {
			fin.close();
		}
		return file; 
	}
	
	
}
