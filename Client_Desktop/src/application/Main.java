package application;
    

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import org.apache.commons.lang3.time.StopWatch;
import com.securityinnovation.jNeo.NtruException;
import javafx.application.Application;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.stage.Stage;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;


public class Main extends Application {
    
    @FXML private TextField text_g;
    @FXML private TextField text_pw;
    @FXML private TextField text_idc;
    @FXML private TextField text_ids;
    @FXML private Button submit;
    @FXML private Label log_label;
    @FXML private Label ssk_label;
    @FXML private Label time_label;
    
    private static Client paper;
    private static Stage primaryStage;
    private static HttpUtil httppost;
        
    @Override
    public void start(Stage primaryStage)
    {
        try {
            Main.primaryStage = primaryStage;
            Main.primaryStage.setTitle("AddressApp");
            
            setOverView();
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
    
    
    public void setOverView()
    {
        try {
            primaryStage = new Stage();
            FXMLLoader loader = new FXMLLoader(Main.class.getResource("/view/Overview.fxml"));
            
            AnchorPane overview = (AnchorPane) loader.load();
            Scene scene = new Scene(overview);
            primaryStage.setScene(scene);
            primaryStage.show();
           
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void setNextView()
    {
        try {
            FXMLLoader loader = new FXMLLoader(Main.class.getResource("/view/Nextview.fxml"));
            
            AnchorPane overview = (AnchorPane) loader.load();
            Scene scene = new Scene(overview);
            
            primaryStage.setScene(scene);
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args)
    {
        paper = new Client();
        httppost = new HttpUtil();
        launch(args);
    }
    
    @FXML
    public void submit(
            ActionEvent event) 
            throws ClassNotFoundException,
                    IOException,
                    NoSuchAlgorithmException,
                    NtruException,
                    InterruptedException
    {
        log_label.setText("");
        ssk_label.setText("");
        time_label.setText("");
        StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        
        try{
            paper.init(
                    text_pw.getText(),
                    text_idc.getText(), 
                    Integer.parseInt(text_g.getText()), 
                    text_ids.getText()
            );
        }catch(NumberFormatException e){
            log_label.setText("g should be number");
            return;
        }
        try{
            paper.clientCalX();
            paper.clientCalAuthcandEnc();
        } catch (FileNotFoundException e){
            log_label.setText("Not Found Public key");
            return;
        }
        String return_string = httppost.do_X_Authc_Post(text_idc.getText(),text_pw.getText());
        if(return_string.equals("pwreject")){
            log_label.setText("idc / pw error ! Reject!");
        }else{
            System.out.println(return_string);
            set_do_X_Authc_Post_return(return_string);
            if(!paper.clientCheckAuths()){
                log_label.setText("Reject!");
            } else{
                String key = paper.clientCalKcAndskc();
                ssk_label.setText(key);
                time_label.setText(stopWatch.toString());
            }
        }
        stopWatch.stop();
        
    }
    
    
    
    
    public void set_do_X_Authc_Post_return(
            String input) 
            throws IOException
    {
        String [] s = input.split("!");
        String [] ws_sp = s[0].split(":");
        String [] Y_sp = s[1].split(":");
        String [] Auths_sp = s[2].split(":");
        
        
        ArrayList<Integer> tmp_ws = new ArrayList<Integer>();
        ws_sp[1] = ws_sp[1].substring(1, ws_sp[1].length()-1);
        String [] a = ws_sp[1].split(",");
            
        for(String x:a) {
            try{
                x = x.trim();
                tmp_ws.add(Integer.parseInt(x));
            }
            catch(NumberFormatException e){
                tmp_ws.add(0);
            }
        }
        paper.set_ws_stream_string(tmp_ws);
            
        ArrayList<Integer> tmp_Y = new ArrayList<Integer>();
        Y_sp[1] = Y_sp[1].substring(1, Y_sp[1].length()-1);
        
        String [] b = Y_sp[1].split(",");
        for(String x:b) {
            try{
                x = x.trim();
                tmp_Y.add(Integer.parseInt(x));
            }
            catch(NumberFormatException e){
                if(x.equals("0"))tmp_Y.add(0);
                else
                    e.printStackTrace();
            }
        }
        paper.set_Y_stream_string(tmp_Y);
        paper.set_Auths(Auths_sp[1]);
    }
    
}
