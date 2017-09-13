package controllers;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import crypto.Crypto;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.stage.Stage;
import javafx.stage.Window;

public class UserPanelController {
	
	private static String PATH = "src/server/users/";
	
	
    private ObservableList<String> data = FXCollections.observableArrayList();
    private String fileName;
    private String fileContent;
    private ObjectOutputStream oos;
    private ObjectInputStream ois;
    private Socket socket;
    private Crypto crypto;
    
    private static final int PORT_NUMBER = 9999;
    //private PrivateKey privateKey = new SignInController().getPrivateKey();
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
    private Button uploadNewButton;
    
    
    @FXML
    private void initialize() {
        
    	try {
            InetAddress iAddress = InetAddress.getByName("127.0.0.1");
            socket = new Socket(iAddress, PORT_NUMBER);
            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
            crypto = new Crypto();
            
        } catch(Exception e) {
        	e.printStackTrace();
        }
        tArea.setVisible(false);
    	logs.setVisible(false);


        try {
			data.addAll(getFileNames(PATH + "user/"));
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
//                        try {
  //                      	tArea.setText(getFileContent(PATH + SignInController.uName + new_val));
							fileName = PATH + "/user/" + new_val;
//							
//						} catch (IOException e) {
//							e.printStackTrace();
//						}
                    
            }
        });
        
       SignInController.stage1.show();
    }
    
    @FXML
    protected void handleSaveButton(ActionEvent event) {
    	
    	try {
    		//writeToFile(fileName, tArea.getText());
    		oos.writeObject("modify");
    		alert("You successfully edited file");
    		tArea.setVisible(false);
    	} catch(IOException ex) {
            Logger.getLogger(UserPanelController.class.getName()).log(Level.SEVERE, null, ex);
    	}
    	
    }
    
    @FXML
    protected void handleEditButton(ActionEvent event) {
        
    	tArea.setVisible(true);
    }
    
    @FXML
    protected void handleShowLogsButton(ActionEvent event) {
        
    	logs.setVisible(true);
    }
    
    @FXML
    protected void handleUploadNewFile(ActionEvent event) {
        FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/uploadNewFileForm.fxml"));
        try {
			Parent root = (Parent) loader.load();

        UserPanelController controller = loader.getController();
        
        Stage stage = new Stage();
        stage.setTitle(" User panel");
        stage.setScene(new Scene(root));  
        stage.show();
//        stage.hide();
		} catch (IOException e) {
			e.printStackTrace();
		}

    }
    
	private String[] getFileNames(String path) throws IOException, ClassNotFoundException, 
		InvalidKeyException, IllegalBlockSizeException, 
		BadPaddingException {
	
		String[] fileNames = null;
		String[] cFileNames;
		String option = "get";
		//oos.writeObject(crypto.EncryptStringAsymmetric(" ", SignInController.privateKey));
		String encOption = crypto.EncryptStringAsymmetric(option, SignInController.privateKey);
		oos.writeObject(encOption);
		cFileNames = (String[]) ois.readObject();
		for(int i = 0; i < cFileNames.length; i++) {
			try {
				fileNames[i] = crypto.DecryptStringSymmetric(cFileNames[i], SignInController.sessionKey);
			} catch (Exception e) {
				e.printStackTrace();
			} 
		}
//		File folder = new File(path);
//		File[] files = folder.listFiles();
//		String[] fileNames = new String[files.length];
//		int j = 0;
//		
//		for(int i = 0; i < files.length; i++) {
//			if(files[i].isFile()) {
//				fileNames[j] = files[i].getName();
//				j++;
//			}
//		}
		return fileNames;
	}
	
//	private String getFileContent(String pathToFile) throws IOException {
//		
//	    StringBuilder sb = new StringBuilder();
//		String line;
//		String content;
//		File file = new File(pathToFile);
//		BufferedReader br = new BufferedReader(new FileReader(file));
//			while((line = br.readLine()) != null) {
//				sb.append(line);
//		        sb.append(System.lineSeparator());
//			}
//			content = sb.toString();
//			System.out.println(content);
//			br.close();
//		return content;
//	}
	
//	private String getFileContent(String pathToFile) throws IOException {
//		
//		String fileContent;
//		
//		
//		return fileContent;
//	}
	
	public void writeToFile(String path, String data) throws IOException {
		File file = new File(path);
		BufferedWriter bw = new BufferedWriter(new FileWriter(file, false));
		
		//bw.append(" ");
		bw.write(data);
		bw.close();
		
	}
	
    private void alert(String message) {

        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("Information");
        alert.setHeaderText(null);
        alert.setContentText(message);

        alert.showAndWait();
    }
   
}
