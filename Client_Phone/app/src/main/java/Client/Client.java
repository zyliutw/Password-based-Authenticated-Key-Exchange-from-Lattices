package Client;
import android.content.Context;
import android.content.ContextWrapper;
import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Sampler;
import it.unisa.dia.gas.jpbc.Vector;
import it.unisa.dia.gas.plaf.jlbc.field.poly.PolyModElement;
import it.unisa.dia.gas.plaf.jlbc.field.poly.PolyModField;
import it.unisa.dia.gas.plaf.jlbc.sampler.gpv08.GPV08FieldSampler;
import it.unisa.dia.gas.plaf.jpbc.field.z.SymmetricZrField;


public class Client extends ContextWrapper {

    private static BigInteger q;
    private PolyModElement<Element> X;
    private PolyModElement<Element> alpha;
    private PolyModElement<Element> Nonce;
    private PolyModElement<Element> Y;
    private PolyModField<Field<Element>> Rq;
    private String idc;
    private String ids;
    private String Auths;
    private String pw;
    private ArrayList<Integer> ws;
    private int g;
    private Sampler sampler;

    public Client(Context base) 
    {
        super(base);
    }


    static Random createSeededRandom() 
    {
        byte seed[] = new byte[32];
        java.util.Random sysRand = new java.util.Random();
        sysRand.nextBytes(seed);
        return new Random(seed);
    }


    private static void encrypt(
            NtruEncryptKey ntruKey,
            Random prng,
            String hashstring,
            String outFileName)
            throws IOException,
                    NtruException
    {
        byte buf[] = hashstring.getBytes();
        byte ivBytes[] = null;
        byte encryptedBuf[] = null;
        byte wrappedAESKey[] = null;

        try {
            // Get an AES key
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            SecretKey aesKey = keygen.generateKey();

            // Get an IV
            ivBytes = new byte[16];
            prng.read(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Encrypt the plaintext, then zero it out
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            encryptedBuf = cipher.doFinal(buf);
            java.util.Arrays.fill(buf, (byte) 0);

            // Wrap the AES key with the NtruEncrypt key
            byte aesKeyBytes[] = aesKey.getEncoded();
            wrappedAESKey = ntruKey.encrypt(aesKeyBytes, prng);
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);

        } catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }

        // Write it to the output file

        FileOutputStream fileOS = new FileOutputStream(outFileName);
        DataOutputStream out = new DataOutputStream(fileOS);
        out.writeInt(ivBytes.length);
        out.write(ivBytes);
        out.writeInt(wrappedAESKey.length);
        out.write(wrappedAESKey);
        out.writeInt(encryptedBuf.length);
        out.write(encryptedBuf);
        out.close();
        fileOS.close();
    }


    private static String Extr(
            Element K, 
            ArrayList<Integer> ws) 
    {
        String out = "";
        Vector k = (Vector) K;

        for (int i = 0; i < k.getSize(); i++) {
            int a = ((Integer.parseInt(k.getAt(i).toString()) + ws.get(i) * (q.intValue() - 1) / 2) % q.intValue()) % 2;
            if (a == -1) a = 1;
            out = out + a;
        }
        return out;
    }


    public void init(
            String pw,
            String idc,
            int g,
            String ids)
    {
        q = new BigInteger("40961");

        SecureRandom random = new SecureRandom();
        int n = 256;
        int sigma = 2;
        int strength = 8;

        Rq = new PolyModField(random, new SymmetricZrField(random, q), n);
        sampler = new GPV08FieldSampler(strength, random, sigma, Rq);
        this.pw = pw;
        this.idc = idc;
        this.g = g;
        this.ids = ids;
    }


    public ArrayList<Integer> clientCalX()
            throws IOException,
                    ClassNotFoundException 
    {
        Element tmp_fc = sampler.sample();
        Element tmp_alpha = sampler.sample();
        Element tmp_Nonce = sampler.sample();

        PolyModElement<Element> fc = new PolyModElement<>(Rq);
        alpha = new PolyModElement<>(Rq);
        Nonce = new PolyModElement<>(Rq);

        fc.set(tmp_fc);
        alpha.set(tmp_alpha);
        Nonce.set(tmp_Nonce);
        PolyModElement<Element> t_alpha = alpha.duplicate();
        PolyModElement<Element> t_fc = fc.duplicate();

        X = t_alpha.mul(g).add(t_fc.mul(2));

        ArrayList<Integer> c = new ArrayList<>();
        X.getCoefficients().forEach((x) -> c.add(Integer.parseInt(x.toString())));


        ObjectOutputStream oos;
        oos = new ObjectOutputStream(new FileOutputStream(getFilesDir().getPath() + "/X"));
        oos.writeObject(c);
        oos.close();

        return c;
    }


    public void clientCalAuthcandEnc() 
            throws IOException,
                    NoSuchAlgorithmException,
                    NtruException 
    {
        String X_idc_pw_nonce = "" + X.toString() + idc + pw + Nonce.toString() + Integer.toString(g);
        String hexString = getHash(X_idc_pw_nonce);

        Random prng = createSeededRandom();
        NtruEncryptKey pubKey = loadKey("pubKey");
        String toEnc = hexString + "" + Nonce.toString();

        encrypt(pubKey, prng, toEnc, getFilesDir().getPath() + "/encry");

    }


    public void set_ws_stream_string(
            ArrayList<Integer> s) 
            throws IOException 
    {
        ws = new ArrayList<>(s);
    }


    public void set_Y_stream_string(
            ArrayList<Integer> s) 
            throws IOException 
    {
        ArrayList<Integer> Y_data = new ArrayList<>(s);
        List<Element> Y_arraylist = new ArrayList<>();
        for (Integer x : Y_data) {
            Element e = Rq.getTargetField().newElement();
            e.set(x);
            Y_arraylist.add(e);
        }

        Y = new PolyModElement<>(Rq, Y_arraylist);
    }


    public void set_Auths(
            String s) 
    {
        Auths = s;
    }


    public Boolean clientCheckAuths() 
            throws NoSuchAlgorithmException,
                    IOException 
    {
        String Y_IDs_pw_ws_Nonce_plus1 = "" + Y.toString() + ids + pw + ws.toString() + Nonce.toString() + 1;
        String hexString = getHash(Y_IDs_pw_ws_Nonce_plus1);
        return Auths.equals(hexString);
    }


    public String clientCalKcAndskc() 
            throws NoSuchAlgorithmException,
                    IOException 
    {
        PolyModElement<Element> rc;
        Element tmp_rc = sampler.sample();
        rc = new PolyModElement<>(Rq);
        rc.set(tmp_rc);

        PolyModElement<Element> t_alpha = alpha.duplicate();
        PolyModElement<Element> t_Y = Y.duplicate();
        PolyModElement<Element> t_rc = rc.duplicate();

        PolyModElement<Element> Kc = t_alpha.mul(t_Y).add(t_rc.mul(2));
        String rhoc = Extr(Kc, ws);

        String IDc_IDs_X_Y_ws_Nonce_rhos = "" + idc + ids + X.toString() + Y.toString() + ws.toString() + Nonce.toString() + rhoc;

        return getHash(IDc_IDs_X_Y_ws_Nonce_rhos);
    }


    private NtruEncryptKey loadKey(
            String keyFileName) 
            throws IOException,
                    NtruException 
    {
        InputStream in = getAssets().open(keyFileName);

        byte buf[] = new byte[in.available()];
        int in_len = in.read(buf);
        in.close();
        NtruEncryptKey k = new NtruEncryptKey(buf);
        java.util.Arrays.fill(buf, (byte) 0);
        return k;
    }


    private String getHash(
            String input) 
            throws IOException,
                    NoSuchAlgorithmException 
    {
        MessageDigest md;
        md = MessageDigest.getInstance("SHA-256");

        md.update(input.getBytes("UTF-8"));
        byte[] digest = md.digest();

        StringBuilder hexString = new StringBuilder();
        for (int i : digest) {
            String hex = Integer.toHexString(0xff & i);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}

