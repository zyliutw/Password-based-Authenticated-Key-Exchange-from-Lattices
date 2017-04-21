package application;
import java.io.File;
import java.io.IOException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;  
import org.apache.http.client.methods.HttpPost;  
import org.apache.http.entity.mime.HttpMultipartMode;  
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils; 



public class HttpUtil {
	
	private static String url = "http://localhost:8080/Server/index";
	HttpClient client;
	
	public HttpUtil(){
		 
         client = HttpClientBuilder.create().build();
	}
	
	public String do_X_Authc_Post(String idc, String pw) throws ClientProtocolException, IOException {
		HttpPost post = new HttpPost( url );  
		MultipartEntityBuilder builder = MultipartEntityBuilder.create();

		builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);  
        File paramValue_X = new File("./X");  
        File paramValue_encry = new File("./encry"); 
 
        // For File parameters  
        builder.addPart( "X", new FileBody((( File ) paramValue_X ) ));
        builder.addPart( "encry", new FileBody((( File ) paramValue_encry ) )); 
        builder.addTextBody("idc", idc);
        builder.addTextBody("pw", pw);
        
        HttpEntity entity = builder.build();

        	post.setEntity(entity);

        	HttpResponse response = client.execute(post);
        	response.getEntity().getContent();
        	String responseString = EntityUtils.toString(response.getEntity(), "UTF-8");
       
        	return responseString;
	}
}
