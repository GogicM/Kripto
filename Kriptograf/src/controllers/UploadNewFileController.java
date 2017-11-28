package controllers;

import javafx.application.Platform;


import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

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
                    String option = "new";
                    String encOption = SignInController.asymmetricCrypto.EncryptStringAsymmetric(option, SignInController.serverPublicKey);
                    String signature = SignInController.asymmetricCrypto.signMessagge(option, SignInController.privateKey);
                    SignInController.oos.writeObject(new String[] {signature, encOption});
                    String encTfieldData = SignInController.asymmetricCrypto.EncryptStringSymmetric(tField.getText(), SignInController.sessionKey);
                    SignInController.oos.writeObject(new String[] {SignInController.asymmetricCrypto.signMessagge(tField.getText(), SignInController.privateKey), encTfieldData});

                    SignInController.oos.writeObject(SignInController.asymmetricCrypto.SymmetricFileEncryption(data.getBytes(), SignInController.sessionKey));
                    String[] signatureAndResponse = (String[]) SignInController.ois.readObject();
                    String response = SignInController.asymmetricCrypto.DecryptStringSymmetric(signatureAndResponse[1], SignInController.sessionKey);
                    if(!SignInController.asymmetricCrypto.verifyDigitalSignature(response, signatureAndResponse[0], SignInController.serverPublicKey)) {
                        UserPanelController.alert("Intrusion has occured! Exiting application...");
                        System.exit(0);

                    }
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
