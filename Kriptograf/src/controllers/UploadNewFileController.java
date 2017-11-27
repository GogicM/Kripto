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
