package controllers;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
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
			String data = UserPanelController.newFileContent.getText();
			String encOption = SignInController.asymmetricCrypto.EncryptStringAsymmetric("modify", SignInController.privateKey);
			SignInController.oos.writeObject(encOption);
			SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringSymmetric(data, SignInController.sessionKey));
//			else {
				//SignInController.alert("File can not be created!");
//			}
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
	

}
