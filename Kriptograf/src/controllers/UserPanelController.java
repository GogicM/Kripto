package controllers;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.Stage;
import server.ServerThread;

public class UserPanelController {

    private static String PATH = "src/server/users";

    protected static ObservableList<String> data = FXCollections.observableArrayList();
    private String fileName;
    private String fileContent;
    private Socket socket;

    private static final int PORT_NUMBER = 9999;
    @FXML
    ListView<String> list;
    @FXML
    private Button saveButton;
    @FXML
    private Button downloadButton;
    @FXML
    private Button showLogsButton;
    @FXML
    private TextArea tArea;
    @FXML
    private TextArea logs;
    @FXML
    private TextArea newFileContent;
    @FXML
    private Button uploadNewButton;

    protected static String newFileData;

    @FXML
    private void initialize() {
        tArea.setVisible(false);
        logs.setVisible(false);
        try {
            String[] fileNames = getFileNames(PATH + ServerThread.getUserName());
            data.addAll(fileNames);

        } catch (ClassNotFoundException | IOException e1) {
            e1.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        list.setItems(data);

        list.getSelectionModel().selectedItemProperty().addListener(
                new ChangeListener<String>() {
            public void changed(ObservableValue<? extends String> ov,
                    String old_val, String new_val) {
                        fileName = PATH + "/user/" + new_val;
            }
        });

        SignInController.stage1.show();
    }

    @FXML
    protected void handleSaveButton(ActionEvent event) {

        try {
            SignInController.oos.writeObject("");
            SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringAsymmetric("modify", SignInController.privateKey));
            SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringSymmetric(tArea.getText(), SignInController.sessionKey));
            if("true".equals(SignInController.asymmetricCrypto.DecryptStringSymmetric((String) SignInController.ois.readObject(), SignInController.sessionKey))) {
                alert("You successfully edited file");
            } else {
                alert("File can not be edited");
            }
            tArea.setVisible(false);
        } catch (Exception ex) {
            Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    @FXML
    protected void handleEditButton(ActionEvent event) {

        tArea.setVisible(true);
        String content = tArea.getText();
        try {
            SignInController.oos.writeObject("");
            SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringAsymmetric("edit", SignInController.privateKey));
            SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringSymmetric(fileName, SignInController.sessionKey));
            tArea.setText(SignInController.asymmetricCrypto.DecryptStringSymmetric((String) SignInController.ois.readObject(), SignInController.sessionKey));
        } catch (IOException ex) {
            Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    @FXML
    protected void handleShowLogsButton(ActionEvent event) {
        try {
            SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringAsymmetric("logs", SignInController.privateKey));
        } catch (Exception e) {
            e.printStackTrace();
        }
        logs.setVisible(true);
    }

    @FXML
    protected void handleUploadNewFile(ActionEvent event) {
        FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/uploadNewFileForm.fxml"));
        try {
            newFileData = newFileContent.getText();
            Parent root = (Parent) loader.load();

            UploadNewFileController controller = loader.getController();

            Stage stage = new Stage();
            stage.setTitle(" User panel");
            stage.setScene(new Scene(root));
            stage.show();
//        stage.hide();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    @FXML
    protected void handleDownloadButton(ActionEvent event) {
        
    }
    private String[] getFileNames(String path) throws IOException, ClassNotFoundException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

        String[] fileNames;
        String[] cFileNames;
        String option = "get";
        String encOption = SignInController.asymmetricCrypto.EncryptStringAsymmetric("get", SignInController.privateKey);
        SignInController.oos.writeObject(encOption);
        SignInController.oos.writeObject(encOption);

        System.out.println("enc OPTION : " + encOption);

        cFileNames = (String[]) SignInController.ois.readObject();
        fileNames = new String[cFileNames.length];
        try {
            fileNames = SignInController.asymmetricCrypto.DecryptStringArraySymmetric(cFileNames, SignInController.sessionKey);

        } catch (Exception e) {

            e.printStackTrace();
        }
        return fileNames;
    }


    protected static void alert(String message) {

        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("Information");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }

    private String getFileContent(String path) {
        String content = "";
        try {
            System.out.println("PATH IN UPALEN CONTR :  " + path);
            SignInController.oos.writeObject("");
            SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringAsymmetric("content", SignInController.privateKey));
            SignInController.oos.writeObject(SignInController.asymmetricCrypto.EncryptStringSymmetric(path, SignInController.sessionKey));
            content = SignInController.asymmetricCrypto.DecryptStringSymmetric((String) SignInController.ois.readObject(), SignInController.sessionKey);
            System.out.println("Content : " + content);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return content;
    }

}
