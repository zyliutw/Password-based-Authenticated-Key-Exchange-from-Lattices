package Client;
import android.os.Bundle;
import android.os.StrictMode;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import com.securityinnovation.jNeo.NtruException;

import org.apache.commons.lang3.time.StopWatch;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;



public class OverViewActivity extends AppCompatActivity {

	private EditText idc_text;
	private EditText pw_text;
	private EditText g_text;
	private EditText ids_text;
	private TextView log;
	private TextView ssk;
	private TextView time;
	private Button submit;
	private Client client;
	private HttpUtil httppost;
	private SubmitListener submitListener;

	@Override
	protected void onCreate(Bundle savedInstanceState) 
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_overview);

		StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
				.detectDiskReads()
				.detectDiskWrites()
				.detectNetwork()
				.penaltyLog()
				.build());

		idc_text = (EditText) findViewById(R.id.idc_text);
		pw_text = (EditText) findViewById(R.id.pw_text);
		g_text = (EditText) findViewById(R.id.g_text);
		ids_text = (EditText) findViewById(R.id.ids_text);
		submit = (Button) findViewById(R.id.button);
		log = (TextView) findViewById(R.id.log);
		ssk = (TextView) findViewById(R.id.ssk);
		time = (TextView) findViewById(R.id.time);

		client = new Client(this);
		httppost = new HttpUtil(this);
		submitListener = new SubmitListener();
		submit.setOnClickListener(submitListener);

	}


	class SubmitListener implements View.OnClickListener 
	{
		public void onClick(
				View v)
		{
			log.setText("");
			ssk.setText("");
			time.setText("");
			StopWatch stopWatch = new StopWatch();
			stopWatch.start();
			try {
				client.init(pw_text.getText().toString(), idc_text.getText().toString(), Integer.parseInt(g_text.getText().toString()), ids_text.getText().toString());
			} catch (NumberFormatException e) {
				log.setText("g should be number");
				return;
			}

			try {
				client.clientCalX();
				client.clientCalAuthcandEnc();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
				log.setText("Not Found Public key");
				return;
			} catch (IOException | NoSuchAlgorithmException | NtruException | ClassNotFoundException e) {
				e.printStackTrace();
				return;
			}

			String return_string = "";
			try {
				return_string = httppost.do_X_Authc_Post(idc_text.getText().toString(), pw_text.getText().toString());
			} catch (IOException e) {
				e.printStackTrace();
			}

			if (return_string.equals("pwreject")) {
				log.setText("idc / pw error ! Reject!");
			} else {
				try {
					set_do_X_Authc_Post_return(return_string);
					if (!client.clientCheckAuths()) {
						log.setText("Reject!");
					} else {
						String key = client.clientCalKcAndskc();
						ssk.setText(key);
						time.setText(stopWatch.toString());
					}
				}
				catch (NoSuchAlgorithmException | IOException e) {
					e.printStackTrace();
				}
			}
		}

		public void set_do_X_Authc_Post_return(
				String input) 
				throws IOException 
		{
			String[] s = input.split("!");
			String[] ws_sp = s[0].split(":");
			String[] Y_sp = s[1].split(":");
			String[] Auths_sp = s[2].split(":");


			ArrayList<Integer> tmp_ws = new ArrayList<>();
			ws_sp[1] = ws_sp[1].substring(1, ws_sp[1].length() - 1);
			String[] a = ws_sp[1].split(",");

			for (String x : a) {
				try {
					x = x.trim();
					tmp_ws.add(Integer.parseInt(x));
				} catch (NumberFormatException e) {
					tmp_ws.add(0);
				}
			}
			client.set_ws_stream_string(tmp_ws);


			ArrayList<Integer> tmp_Y = new ArrayList<>();
			Y_sp[1] = Y_sp[1].substring(1, Y_sp[1].length() - 1);

			String[] b = Y_sp[1].split(",");
			for (String x : b) {
				try {
					x = x.trim();
					tmp_Y.add(Integer.parseInt(x));
				} catch (NumberFormatException e) {
					if (x.equals("0")) tmp_Y.add(0);
					else
						e.printStackTrace();
				}
			}
			client.set_Y_stream_string(tmp_Y);
			client.set_Auths(Auths_sp[1]);
		}
	}
}

