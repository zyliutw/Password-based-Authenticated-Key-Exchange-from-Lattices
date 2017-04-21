package Main;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.servlet.ServletRequestContext;
import com.securityinnovation.jNeo.NtruException;

@SuppressWarnings("serial")
@WebServlet(name = "Index", urlPatterns = { "/index" })
public class Index extends HttpServlet {

	private String pw;
	private String idc;
	private String Auths;
	private ArrayList<Integer> Y;
	private ArrayList<Integer> ws;
	private String ssk;
	
	@SuppressWarnings("unchecked")
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		ServletContext servletContext = getServletContext();
		String saveDirectory = servletContext.getRealPath("/upload");

		FileItemFactory factory = new DiskFileItemFactory();
		ServletFileUpload upload = new ServletFileUpload(factory);

		try {
			List<FileItem> items = upload.parseRequest(new ServletRequestContext(req));
			Iterator<FileItem> iterator = items.iterator();
			while (iterator.hasNext()) {
				FileItem item = (FileItem) iterator.next();
				String name = item.getFieldName();
				if (item.isFormField()) {
					if (name.equals("pw")) {
						pw = item.getString();
					} else if (name.equals("idc")) {
						idc = item.getString();
					}
				} else {
					if (name.equals("X")) {
						File uploadedFile = new File(saveDirectory, "X");
						item.write(uploadedFile);
					} else {
						File uploadedFile = new File(saveDirectory, "encry");
						item.write(uploadedFile);
					}
				}
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		ObjectInputStream objInputStream = new ObjectInputStream(
				new FileInputStream(servletContext.getRealPath("/upload/X")));
		ArrayList<Integer> X_data = null;
		try {
			X_data = (ArrayList<Integer>) objInputStream.readObject();
		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		objInputStream.close();

		Server_Calculate calculate = new Server_Calculate();
		
		if(!calculate.checkpw(idc, pw)){
			resp.setContentType("application/text");
			resp.getWriter().print("pwreject");
		} else{
			calculate.init(pw,  idc,  X_data);

			File pkFile = new File(servletContext.getRealPath("/WEB-INF/privKey"));
			long pklen = pkFile.length();
			InputStream privKey = servletContext.getResourceAsStream("/WEB-INF/privKey");

			File enFile = new File(servletContext.getRealPath("/upload/encry"));
			DataInputStream enFileStream = new DataInputStream(new FileInputStream(enFile));

			try {
				calculate.checkAuthcAndDec(privKey, pklen, enFileStream);

				if (!calculate.checkHashValue()) {
					resp.setContentType("application/text");
					resp.getWriter().print("reject");
				} else {
					Y = calculate.serverCalY();
					ws = calculate.serverCalws();

				
					ssk = calculate.serverCalsks();
					Auths = calculate.serverCalAuths();

					resp.setContentType("application/text");
					resp.getWriter().print("ws:" + ws + '!' + "Y:" + Y + "!" + "Auths:" + Auths);

				}
			} catch (NtruException | NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		}
		

	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setAttribute("g", 1000);
		req.setAttribute("ids", "server1");
		req.setAttribute("ssk", ssk);
		req.getRequestDispatcher("index.jsp").forward(req, resp);

		return;
	}

}
