package Main;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@SuppressWarnings("serial")
@WebServlet(name = "PublicKey", urlPatterns = { "/publickey" })
public class PublicKey extends HttpServlet {

    @Override
    protected void doGet(
            HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException,
                    IOException 
    {
        ServletContext servletContext = getServletContext();

        File pkfile = new File(servletContext.getRealPath("/download/pubKey"));
        resp.reset();
        resp.setContentType("application/octet-stream");
        String encodingFilename = new String("public key");
        System.out.println("encodingFilename:" + encodingFilename);
        resp.setHeader("content-disposition", "attachment;filename=" + encodingFilename);
        InputStream in = new FileInputStream(pkfile);
        OutputStream out = resp.getOutputStream();
        byte[] b = new byte[1024];
        int n = 0;
        while ((n = in.read(b)) != -1) {
            out.write(b, 0, n);
        }
        out.flush();
        in.close();
        out.close();

    }
}
