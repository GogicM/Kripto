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
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
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
import server.ServerThread;

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

    public static Stage stage1 = new Stage();
    private Stage stage = new Stage();
    private static final int PORT_NUMBER = 9999;
    protected static ObjectOutputStream oos;
    protected static ObjectInputStream ois;
    private static Socket socket;
    protected static Crypto asymmetricCrypto;
    protected static SecretKey sessionKey;
    private static X509Certificate certificate;
    private static String username;
    private PublicKey publicKey;
    protected static PrivateKey privateKey;
    protected static PublicKey serverPublicKey;
    private final Desktop desktop = Desktop.getDesktop();
    public static String uName;
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

        InetAddress iAddress;

        try {
            iAddress = InetAddress.getByName("127.0.0.1");

            socket = new Socket(iAddress, PORT_NUMBER);
            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @FXML
    protected void handleSignInButton(ActionEvent event) {

        if (!uNameTextField.getText().isEmpty() && !pTextField.getText().isEmpty()) {
            uName = uNameTextField.getText();
            password = pTextField.getText();
            // String option = "login";

            try {

                asymmetricCrypto = new Crypto();
                if (new File("src\\keys\\" + uName + "Public.der").exists()) {
                    publicKey = asymmetricCrypto.getPublicKey("src\\keys\\" + uName + "Public.der");
                    privateKey = asymmetricCrypto.getPrivateKey("src\\keys\\" + uName + "DER.key");
                    //Exchange of keys for asymmetric crypto
                    //send public key to server
                    oos.writeObject(publicKey);
                    
                    byte[] keyFromServer = (byte[]) ois.readObject();
                    int length = asymmetricCrypto.AsymmetricFileDecription(keyFromServer, privateKey).length;
                    //sessionKey for symmetric encryption
                    sessionKey = new SecretKeySpec(asymmetricCrypto.AsymmetricFileDecription(keyFromServer, privateKey),
                            0, length, "AES");
                    //login went well, now client sends certificate				                 
                    serverPublicKey = (PublicKey) ois.readObject();
                    boolean login;
                    do {
                        login = loginCheck(uName, password);
                        //    }
                        System.out.println("LOGIN : " + login);
                        if (!login) {
                            alert("Wrong user name or password!");
                        }
                    } while (!login);

                    browseLabel.setVisible(true);
                    addCertLabel.setVisible(true);
                    browse.setVisible(true);

                } else {
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
        System.out.println("FILE NAME : " + file.getName().split("\\.")[0]);
        if(!uName.equals(file.getName().split("\\.")[0])) {
        	alert("Certificate not compatibile to this user.");
        	send.setVisible(false);
        }
        setText(file.getName());
        if (browseLabel.getText() != null && uName.equals(file.getName().split("\\.")[0])) {
            send.setVisible(true);
        }

    }

    @FXML
    protected void handleSendButton(ActionEvent event) {
        try {

            if (sendCertificate(uName)) {

                FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/userPanel.fxml"));
                System.out.println("Proslo");
                Parent root = (Parent) loader.load();

                UserPanelController controller = loader.getController();

                stage1.setTitle(" User panel");
                stage1.setScene(new Scene(root));
                stage1.show();

                stage.hide();
            }
        } catch (Exception ex) {
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
            BadPaddingException, NoSuchAlgorithmException, ClassNotFoundException, 
            InvalidKeySpecException, SignatureException {

        boolean login = false;
        String option = "login";
        String encryptedUname;
        String encryptedPassword;
        //for some reason, first writeObject dissappears, so I had to send empty String
        oos.writeObject("");
        String signature = asymmetricCrypto.signMessagge(option, privateKey);
       // String signedEncOption = asymmetricCrypto.signMessagge(option, privateKey);
        String encOption = asymmetricCrypto.EncryptStringAsymmetric(option, serverPublicKey);
        String[] signatureAndOption = new String[]{signature, encOption};
        System.out.println("SIGNATURE LENGTH : " + signatureAndOption[0].getBytes().length + " AND OPTION : " + signatureAndOption[1]);
        //encrypt option and send to server
        oos.writeObject(signatureAndOption);
        //encrypt username and send to server#
        encryptedUname = asymmetricCrypto.EncryptStringAsymmetric(username, serverPublicKey);
        oos.writeObject(new String[] {asymmetricCrypto.signMessagge(option, privateKey), encryptedUname});
        //encrypt password and send to server
        String securePassword = cipher(password);
        encryptedPassword = asymmetricCrypto.EncryptStringAsymmetric(securePassword, serverPublicKey);
        oos.writeObject(new String[] {asymmetricCrypto.signMessagge(option, privateKey), encryptedPassword});
        login = Boolean.valueOf(ois.readObject().toString());

        return login;
    }

    private boolean sendCertificate(String uName) throws IOException, ClassNotFoundException,
            GeneralSecurityException {

        String value = "";

        boolean isGood = false;
        String option = "cert";

        oos.writeObject("");
        
        String optionEncrypted = asymmetricCrypto.EncryptStringAsymmetric(option, serverPublicKey);
        String signature = asymmetricCrypto.signMessagge(option, privateKey);
        oos.writeObject(new String[] {signature, optionEncrypted});
        certificate = asymmetricCrypto.getCertificate("src\\certificates\\" + uName + ".crt");
        System.out.println("CERTIFICATE SIZE : " + certificate.getEncoded().length + "SIGNED CERT SIZE : " + asymmetricCrypto.signMessagge(certificate.toString(), privateKey).getBytes().length);
        byte[] array = concatanateByteArrays(asymmetricCrypto.signMessagge(certificate.toString(), privateKey).getBytes(), certificate.getEncoded());
        
        oos.writeObject(asymmetricCrypto.SymmetricFileEncryption(array, sessionKey));
        System.out.println("SIZE OF CERT : " + certificate.getEncoded().length + "size of signature : " + asymmetricCrypto.signMessagge(certificate.toString(), privateKey).getBytes().length);
        String cn = certificate.getSubjectX500Principal().toString().split(",")[0];
        System.out.println("SIZE OF CN : " + cn.getBytes().length);
        oos.writeObject(asymmetricCrypto.EncryptStringSymmetric(cn, sessionKey));
        String[] dataFromServer = (String[]) ois.readObject();
                value = asymmetricCrypto.DecryptStringSymmetric(dataFromServer[1], sessionKey);
        if(!asymmetricCrypto.verifyDigitalSignature(value, dataFromServer[0], serverPublicKey)) {
        	alert("Intrusion has occured! Exiting application...");
        	System.exit(0);
        }
        if (("true").equals(value)) {
            isGood = true;
        }

        return isGood;
    }

    protected static void alert(String message) {

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

    protected PrivateKey getPrivateKey() {
        return privateKey;
    }
    /*
     * Method that takes two byte arrays and concatenate them into one, appending one to another
     * 
     */
    private byte[] concatanateByteArrays(byte[] first, byte[] second) {
    	
    	//byte[] concatanated = new byte[(int) first.length + (int) second.length];
    	ByteArrayOutputStream output = new ByteArrayOutputStream();

    	try {
			output.write(first);
	    	output.write(second);

		} catch (IOException e) {
			e.printStackTrace();
		}
    	System.out.println("FIRST's size :" +first.length + "second's size: " + second.length);
    	byte[] concatanated = output.toByteArray();
    	System.out.println("output's size :" + concatanated.length);

    	return concatanated;
    }
}
