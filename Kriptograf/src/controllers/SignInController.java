/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controllers;

import java.net.InetAddress;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import java.security.PrivateKey;
import crypto.Crypto;
import java.awt.Desktop;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.beans.property.StringProperty;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.apache.commons.codec.digest.DigestUtils;

/**
 *
 * @author Milan
 */
public class SignInController {
	
	private Stage stage = new Stage();
    private static final int PORT_NUMBER = 9999;
    private static ObjectOutputStream oos;
    private static ObjectInputStream ois;
    private static Socket socket;
    private static Crypto asymmetricCrypto;
    private static SecretKey sessionKey;
    private static X509Certificate certificate;
    private static String username;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private final Desktop desktop = Desktop.getDesktop();
    private String uName;
    private String password;
    @FXML
    private Button signIn;
    @FXML
    private TextField uNameTextField;
    @FXML
    private PasswordField pTextField;
    @FXML
    private Button browse;
    @FXML
    private Button send;
    @FXML
    private Label browseLabel;
    @FXML
    private Label addCertLabel;

    @FXML
    private void initialize() {

        send.setVisible(false);
          browseLabel.setVisible(false);
          addCertLabel.setVisible(false);
          browse.setVisible(false);
    }

    @FXML
    protected void handleSignInButton(ActionEvent event) {

        if(!uNameTextField.getText().isEmpty() && !pTextField.getText().isEmpty()) {
            uName = uNameTextField.getText();
            password = pTextField.getText();
            // String option = "login";
            
            try {
                InetAddress iAddress = InetAddress.getByName("127.0.0.1");
                socket = new Socket(iAddress, PORT_NUMBER);
                oos = new ObjectOutputStream(socket.getOutputStream());
                ois = new ObjectInputStream(socket.getInputStream());
                asymmetricCrypto = new Crypto();
                if(new File("src\\keys\\" + uName + "Public.der").exists()) {
	                publicKey = asymmetricCrypto.getPublicKey("src\\keys\\" + uName + "Public.der");
	                privateKey = asymmetricCrypto.getPrivateKey("src\\keys\\" + uName + "DER.key");
	                //Exchange of keys for asymmetric crypto
	                //send public key to server
	                oos.writeObject(publicKey);
		            System.out.println("USLO U LOGIN CHECK CLIENT SIDE!");
		            // boolean b = Boolean.valueOf(ois.readObject().toString());
		            byte[] keyFromServer = (byte[]) ois.readObject();
		            System.out.println("KEY FROM SERVER " + keyFromServer);
		            int length = asymmetricCrypto.AsymmetricFileDecription(keyFromServer, privateKey).length;
		            //sessionKey for symmetric encryption
		            sessionKey = new SecretKeySpec(asymmetricCrypto.AsymmetricFileDecription(keyFromServer, privateKey),
		                   0, length, "AES");
		            //login went well, now client sends certificate
		            System.out.println("SESSION KEY : " + sessionKey.toString());
		            //alert("Wrong username or password!");

				                 
				                    //cert loaded, next is to send cert to server
			   

	                boolean login;
	              do {
	            	  login = loginCheck(uName, password);
	            //    }
	                } while(!login);
	           	                		
		             browseLabel.setVisible(true);
	                 addCertLabel.setVisible(true);
	                 browse.setVisible(true);
//	            	 if (!loginCheck(uName, password)) {
//	                	}
                }
                else {
                	alert("Username doesn't exist!");
                }
//            	oos.flush();
//            	oos.close();
//            	ois.close();
//            	socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            } 
         } else {
        	 alert("Username or password field can not be empty!");
        }
    
    }
    @FXML
    protected void handleBrowseButton(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        configureFileChooser(fileChooser);
        File file = new File("src/certificates");
        if (file.exists()) {
            //bug in FileChooser, one must set initial directory or it will throw exception
            fileChooser.setInitialDirectory(file);
        }
        file = fileChooser.showOpenDialog(getStage());
        setText(file.getName());
        if (browseLabel.getText() != null) {
            send.setVisible(true);
        }
//        if (file != null) {
//            openFile(file);
//        }

    }
    
    @FXML
    protected void handleSendButton(ActionEvent event) {
        try {
            if (sendCertificate(uName)) {
                FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/userPanel.fxml"));
                Parent root = (Parent) loader.load();
                UserPanelController controller = loader.getController();
//                controller.setStage(stage);
//                stage.setTitle("Welcome ");
//                stage.setScene(new Scene(root, 450, 350));
//                stage.show();
                Stage stage1 = new Stage();
                stage1.setTitle(" User panel");
                stage1.setScene(new Scene(root));  
                stage1.show();
            }
        } catch (IOException ex) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateEncodingException ex) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, ex);
		} catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, ex);
		}
    }

    private static void configureFileChooser(final FileChooser fileChooser) {

        fileChooser.setTitle("Select your certificate");
        fileChooser.setInitialDirectory(new File("../certificates"));
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("CRT", "*.crt"));
    }

    private void openFile(File file) {
        try {
            desktop.open(file);
        } catch (IOException e) {
            Logger.getLogger(SignInController.class.getName()).log(Level.SEVERE, null, e);
        }
    }

    public void setStage(Stage stage) {
        this.stage = stage;
    }

    public Stage getStage() {
        return stage;
    }

    public void setText(String text) {
        browseLabel.setText(text);
    }

    private boolean loginCheck(String username, String password) throws IOException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, NoSuchAlgorithmException, ClassNotFoundException {

        boolean login = false;
        String option = "login";
        String encryptedUname;
        String encryptedPassword;
        //for some reason, first writeObject dissappears, so I had to send empty String
        oos.writeObject("");
        String encOption = asymmetricCrypto.EncryptStringAsymmetric(option, privateKey);
        //encrypt option and send to server
        oos.writeObject(encOption);
        //encrypt username and send to server#
        encryptedUname = asymmetricCrypto.EncryptStringAsymmetric(username, privateKey);
        oos.writeObject(encryptedUname);
        //encrypt password and send to server
        String securePassword = cipher(password);
        encryptedPassword = asymmetricCrypto.EncryptStringAsymmetric(securePassword, privateKey);
        oos.writeObject(encryptedPassword);
        login = Boolean.valueOf(ois.readObject().toString());
        

        return login;
    }
    
    private boolean sendCertificate(String uName) throws InvalidKeyException,
    			IllegalBlockSizeException, BadPaddingException, 
    			IOException, CertificateException, ClassNotFoundException,
    			NoSuchAlgorithmException {
    	
    	boolean isGood = false;
    	String option = "cert";
    	
    	oos.writeObject("");

    	String optionEncrypted = asymmetricCrypto.EncryptStringAsymmetric(option, privateKey);
    	oos.writeObject(optionEncrypted);
        certificate = asymmetricCrypto.getCertificate("src\\certificates\\" + uName + ".crt");
    	oos.writeObject(asymmetricCrypto.SymmetricFileEncryption(certificate.getEncoded(), sessionKey));	
        isGood = Boolean.valueOf(ois.readObject().toString());
        
    	return isGood;
    }

    private void alert(String message) {

        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Error occured");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }

    //sha256 + salt for password storing on server
    private String getSHA256SecurePassword(String password, byte[] salt) {
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    //method for generating salt
    private byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }
    
    private String cipher(String password) {
        return DigestUtils.sha256Hex(password);
    }
}
