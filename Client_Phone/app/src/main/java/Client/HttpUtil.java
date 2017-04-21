package Client;
import android.content.Context;
import android.content.ContextWrapper;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import java.io.File;
import java.io.IOException;

public class HttpUtil extends ContextWrapper {

    HttpClient client;

    public HttpUtil(Context base) {
        super(base);
        client = HttpClientBuilder.create().build();
    }

    public String do_X_Authc_Post(String idc, String pw) throws IOException {
        String url = "http://127.0.0.1:8080/Server/index";
        HttpPost post = new HttpPost(url);
        MultipartEntityBuilder builder = MultipartEntityBuilder.create();

        builder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
        File paramValue_X = new File(getFilesDir().getPath() + "/X");
        File paramValue_encry = new File(getFilesDir().getPath() + "/encry");

        // For File parameters  
        builder.addPart("X", new FileBody(paramValue_X));
        builder.addPart("encry", new FileBody(paramValue_encry));
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
