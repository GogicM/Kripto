package controllers;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.stage.Stage;

public class UserPanelController {
	
	private static String PATH = "src/files/";
	

    ObservableList<String> data = FXCollections.observableArrayList();
    String fileName;
    String fileContent;
	@FXML
    ListView<String> list = new ListView<String>();
    @FXML
    private Button saveButton;
    @FXML
    private Button downloadButton;
    @FXML
    private Button showLogsButton;
    @FXML
    private TextArea tArea = new TextArea();
    
    
    public void start(Stage stage) {
        VBox box = new VBox();
        Button save = new Button();
        save.setText("Save");
        Scene scene = new Scene(box, 300, 300);
        stage.setScene(scene);
        stage.setTitle("ListViewSample");
        box.getChildren().addAll(list, tArea, save);
        VBox.setVgrow(list, Priority.ALWAYS);
        data.addAll(getFileNames(PATH));
        tArea.setLayoutX(100);
        tArea.setLayoutY(300);
        tArea.setFont(Font.font("Verdana", 20));
 
        list.setItems(data);
 
 
        list.getSelectionModel().selectedItemProperty().addListener(
            new ChangeListener<String>() {
                public void changed(ObservableValue<? extends String> ov, 
                    String old_val, String new_val) {
                        try {
                        	tArea.setText(getFileContent(PATH + new_val));
							fileName = PATH + new_val;
							
						} catch (IOException e) {
							e.printStackTrace();
						}
                    
            }
        });
        
        save.setOnAction(new EventHandler<ActionEvent> () {
        	 @Override public void handle(ActionEvent e) {
        		 try {
					writeToFile(fileName, tArea.getText());
				} catch (IOException e1) {
					e1.printStackTrace();
				}
        	 }
        });
        stage.show();
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

}
