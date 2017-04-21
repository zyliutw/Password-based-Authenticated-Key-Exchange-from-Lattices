package Main;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.io.InputStream;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import com.securityinnovation.jNeo.Random;
import com.securityinnovation.jNeo.NtruException;
import com.securityinnovation.jNeo.OID;
import com.securityinnovation.jNeo.ntruencrypt.NtruEncryptKey;
import it.unisa.dia.gas.plaf.jlbc.field.poly.PolyModElement;
import it.unisa.dia.gas.plaf.jlbc.field.poly.PolyModField;
import it.unisa.dia.gas.plaf.jlbc.sampler.gpv08.GPV08FieldSampler;
import it.unisa.dia.gas.plaf.jpbc.field.z.SymmetricZrField;
import it.unisa.dia.gas.jpbc.*;

public class Server_Calculate {

    public static BigInteger q;

    // client
    public PolyModElement<Element> X;
    public PolyModElement<Element> fc;
    public PolyModElement<Element> alpha;
    public String Nonce;
    public String idc;
    public PolyModElement<Element> Kc;
    public PolyModElement<Element> rc;
    String client_Authc;

    // server
    public PolyModElement<Element> Y;
    public PolyModElement<Element> fs;
    public PolyModElement<Element> beta;
    public String ids;
    public PolyModElement<Element> Ks;
    public PolyModElement<Element> rs;

    // share
    public ArrayList<Integer> ws;
    public int g;
    public String pw;

    private PolyModField<Field<Element>> Rq;
    private Sampler sampler;
    public MessageDigest md;
    
    public Map<String, String> idc_pw_map;

    
    
    public Server_Calculate() 
    {
        idc_pw_map = new HashMap<String, String>();
        idc_pw_map.put("client1", "client1");
        idc_pw_map.put("client2", "client2");
        idc_pw_map.put("client3", "client3");
        idc_pw_map.put("client4", "client4");
    }


    public Boolean checkpw(String idc, String pw)
    {
        if(!idc_pw_map.containsKey(idc)){
            return false;
        } else{
            if(!idc_pw_map.get(idc).equals(pw)){
                return false;
            } else{
                return true;
            }
        }
    }


    @SuppressWarnings("unchecked")
    public void init(
            String pw,
            String idc,
            ArrayList<Integer> X)
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
        this.g = 1000;
        this.ids = "server1";

        List<Element> x_arraylist = new ArrayList<>();
        for (Integer x : X) {
            Element e = Rq.getTargetField().newElement();
            e.set(x);
            x_arraylist.add(e);
        }
        this.X = new PolyModElement<Element>(Rq, x_arraylist);
    }


    public String getAuthcHash(
            String input)
    {
        return input.substring(0, 64);
    }


    public void setNonce(
            String input)
    {
        String nonce = input.substring(64, input.length());
        Nonce = nonce;
    }


    public void checkAuthcAndDec(
            InputStream pk,
            long pklen,
            DataInputStream enFile)
            throws IOException,
                    NtruException 
    {
        NtruEncryptKey privKey = loadKey(pk, pklen);
        client_Authc = decrypt(privKey, enFile);
        setNonce(client_Authc);
    }


    public Boolean checkHashValue() 
            throws NoSuchAlgorithmException,
                    UnsupportedEncodingException 
    {
        md = MessageDigest.getInstance("SHA-256");

        String X_idc_pw_nonce = "" + X.toString() + idc + pw + Nonce + Integer.toString(g);
        md.update(X_idc_pw_nonce.getBytes("UTF-8"));
        byte[] digest = md.digest();

        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            String hex = Integer.toHexString(0xff & digest[i]);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString().equals(client_Authc.substring(0, 64));
    }


    public ArrayList<Integer> serverCalY() 
    {
        Element tmp_fs = sampler.sample();
        Element tmp_beta = sampler.sample();

        fs = new PolyModElement<Element>(Rq);
        beta = new PolyModElement<Element>(Rq);
        fs.set(tmp_fs);
        beta.set(tmp_beta);

        PolyModElement<Element> t_beta = beta.duplicate();
        PolyModElement<Element> t_fs = fs.duplicate();

        Y = t_beta.mul(g).add(t_fs.mul(2));

        ArrayList<Integer> c = new ArrayList<Integer>();
        for (Element x : Y.getCoefficients()) {
            c.add(Integer.parseInt(x.toString()));
        }
        return c;
    }

    public ArrayList<Integer> serverCalws() 
            throws NoSuchAlgorithmException,
                    UnsupportedEncodingException 
    {
        Element tmp_rs = sampler.sample();
        rs = new PolyModElement<Element>(Rq);
        rs.set(tmp_rs);

        PolyModElement<Element> t_beta = beta.duplicate();
        PolyModElement<Element> t_X = X.duplicate();
        PolyModElement<Element> t_rs = rs.duplicate();

        Ks = t_beta.mul(t_X).add(t_rs.mul(2));
        ws = Signal_function(Ks);

        return ws;
    }


    public String serverCalsks() 
            throws NoSuchAlgorithmException,
                    UnsupportedEncodingException 
    {
        String rhos = Extr(Ks, ws);

        md = MessageDigest.getInstance("SHA-256");
        String IDc_IDs_X_Y_ws_Nonce_rhos = "" + idc + ids + X.toString() + Y.toString() + ws.toString() + Nonce + rhos;
        md.update(IDc_IDs_X_Y_ws_Nonce_rhos.getBytes("UTF-8"));

        byte[] digest = md.digest();
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            String hex = Integer.toHexString(0xff & digest[i]);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();

    }

    public String serverCalAuths() 
            throws NoSuchAlgorithmException,
                    UnsupportedEncodingException 
    {

        md = MessageDigest.getInstance("SHA-256");
        String Y_IDs_pw_ws_Nonce_plus1 = "" + Y.toString() + ids + pw + ws.toString() + Nonce + 1;
        md.update(Y_IDs_pw_ws_Nonce_plus1.getBytes("UTF-8"));
        byte[] digest = md.digest();

        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            String hex = Integer.toHexString(0xff & digest[i]);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();

    }


    static OID parseOIDName(
            String requestedOid) 
    {
        try {
            return OID.valueOf(requestedOid);
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid OID! Valid values are:");
            for (OID oid : OID.values())
                System.out.println("  " + oid);
            System.exit(1);
        }
        return null;
    }


    static Random createSeededRandom() 
    {
        byte seed[] = new byte[32];
        java.util.Random sysRand = new java.util.Random();
        sysRand.nextBytes(seed);
        Random prng = new Random(seed);
        return prng;
    }


    public static NtruEncryptKey loadKey(
            InputStream in,
            long pklen) 
            throws IOException,
                    NtruException 
    {
        byte buf[] = new byte[(int) pklen];
        in.read(buf);
        in.close();
        NtruEncryptKey k = new NtruEncryptKey(buf);
        java.util.Arrays.fill(buf, (byte) 0);
        return k;
    }


    public static String decrypt(
            NtruEncryptKey ntruKey,
            DataInputStream in) 
            throws IOException,
                    NtruException 
    {
        byte[] output = null;
        byte ivBytes[] = new byte[in.readInt()];
        in.readFully(ivBytes);
        byte wrappedKey[] = new byte[in.readInt()];
        in.readFully(wrappedKey);
        byte encFileContents[] = new byte[in.readInt()];
        in.readFully(encFileContents);

        try {
            // Unwrap the AES key
            byte aesKeyBytes[] = ntruKey.decrypt(wrappedKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            java.util.Arrays.fill(aesKeyBytes, (byte) 0);

            // Decrypt the file contents
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            output = cipher.doFinal(encFileContents);
        } catch (java.security.GeneralSecurityException e) {
            System.out.println("AES error: " + e);
        }

        return new String(output, "UTF-8");
    }


    private static ArrayList<Integer> Signal_function(
            Element input) 
    {
        ArrayList<Integer> out = new ArrayList<>(2);

        double left = -1 * Math.floor(q.intValue() / 4);
        double right = Math.floor(q.intValue() / 4);

        Vector k = (Vector) input;
        for (int i = 0; i < k.getSize(); i++) {
            int t = Integer.parseInt(k.getAt(i).toString());

            if (t <= right && t >= left) {
                out.add(0);
            } else {
                out.add(1);
            }
        }

        return out;
    }

    private static String Extr(
            Element K,
            ArrayList<Integer> ws)
    {
        String out = "";

        Vector k = (Vector) K;
        for (int i = 0; i < k.getSize(); i++) {
            int a = (int) (((Integer.parseInt(k.getAt(i).toString()) + ws.get(i) * (q.intValue() - 1) / 2)
                    % q.intValue()) % 2);
            if (a == -1)
                a = 1;
            out = out + a;
        }
        return out;
    }


    public void serverGenKey() 
            throws IOException,
                    NtruException
    {
        String pubkeyFile = "./pubKey";
        String privkeyFile = "./privKey";
        String oidstring = "ees1499ep1";

        OID oid = parseOIDName(oidstring);
        Random prng = createSeededRandom();

        NtruEncryptKey k = NtruEncryptKey.genKey(oid, prng);

        FileOutputStream pubFile = new FileOutputStream(pubkeyFile);
        pubFile.write(k.getPubKey());
        pubFile.close();

        FileOutputStream privFile = new FileOutputStream(privkeyFile);
        privFile.write(k.getPrivKey());
        privFile.close();
    }
}
