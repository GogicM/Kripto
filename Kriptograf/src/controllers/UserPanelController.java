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
import java.util.logging.Level;
import java.util.logging.Logger;

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
    private Crypto asymmetricCrypto;
    
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
    private Button uploadNewButton;
    
    
    @FXML
    private void initialize() {
    	
        tArea.setVisible(false);
    	logs.setVisible(false);

        System.out.println("FILE NAMES : " + getFileNames(PATH + "user/"));

        data.addAll(getFileNames(PATH + "user/"));
        list.setItems(data);
        
        try {
            InetAddress iAddress = InetAddress.getByName("127.0.0.1");
            socket = new Socket(iAddress, PORT_NUMBER);
            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
            asymmetricCrypto = new Crypto();
            
        } catch(Exception e) {
        	e.printStackTrace();
        }
 
        list.getSelectionModel().selectedItemProperty().addListener(
            new ChangeListener<String>() {
                public void changed(ObservableValue<? extends String> ov, 
                    String old_val, String new_val) {
                        try {
                        	tArea.setText(getFileContent(PATH + "/user/" + new_val));
							fileName = PATH + "/user/" + new_val;
							
						} catch (IOException e) {
							e.printStackTrace();
						}
                    
            }
        });
        
       SignInController.stage1.show();
    }
    
    @FXML
    protected void handleSaveButton(ActionEvent event) {
    	
    	try {
    		writeToFile(fileName, tArea.getText());
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
    protected void uploadNewFileHandler(ActionEvent event) {
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
	
	private String getFileContent(String pathToFile) throws IOException {
		
	    StringBuilder sb = new StringBuilder();
		String line;
		String content;
		File file = new File(pathToFile);
		BufferedReader br = new BufferedReader(new FileReader(file));
			while((line = br.readLine()) != null) {
				sb.append(line);
		        sb.append(System.lineSeparator());
			}
			content = sb.toString();
			System.out.println(content);
			br.close();
		return content;
	}
	
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
