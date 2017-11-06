package controllers;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import javafx.application.Platform;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import javafx.stage.Window;
import server.ServerThread;

public class UploadNewFileController {

	private static final String PATH = "src/server/users/";

	@FXML
	private Button uploadButton;
	@FXML
	private TextField tField;
	
	@FXML
	protected void uploadButtonHandler(ActionEvent event) {
		try {
                    String data = UserPanelController.newFileData;
                    SignInController.oos.writeObject("");
                    String encOption = SignInController.asymmetricCrypto.EncryptStringAsymmetric("new", SignInController.privateKey);
                    SignInController.oos.writeObject(encOption);
                    SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringSymmetric(tField.getText(), SignInController.sessionKey));

                    SignInController.oos.writeObject(SignInController.asymmetricCrypto.SymmetricFileEncryption(data.getBytes(), SignInController.sessionKey));
                    String response = SignInController.asymmetricCrypto.DecryptStringSymmetric((String) SignInController.ois.readObject(), SignInController.sessionKey);
                    if("true".equals(response)) {
                        UserPanelController.alert("You succesfuly created file");
                    } else {
                         UserPanelController.alert("File can not be created");  
                         Platform.exit();
                    }
                   ((Stage)(((Button)event.getSource()).getScene().getWindow())).close();

                    } catch(Exception e) {
			e.printStackTrace();
                    }
	}
	

}
