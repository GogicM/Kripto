package securedatastorage;

import controllers.SignInController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class SecureDataStorage extends Application {
	   	
		@Override
	    public void start(final Stage primaryStage) throws Exception {
	        FXMLLoader loader = new FXMLLoader(getClass().getClassLoader().getResource("fxml/loginForm.fxml"));
	        Parent root = loader.load();
	        SignInController controller = loader.getController();
	        controller.setStage(primaryStage);
	        primaryStage.setTitle("Welcome!");
	        primaryStage.setScene(new Scene(root, 450, 350));
	        primaryStage.show();
	    }

	    /**
	     * @param args the command line arguments
	     */
	    public static void main(String[] args) {
	        launch(args);
	    }
}
