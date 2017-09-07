package crypto;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Crypto {

	   private Cipher asymmCipher;
	    //one cipher for asymmetric and one for symmetric
	    private Cipher symmCipher;

	    public Crypto() throws NoSuchAlgorithmException, NoSuchPaddingException {
	        this.asymmCipher = Cipher.getInstance("RSA");
	        // this.asymmCipher.init(keylength);
	        this.symmCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    }

	    /*
	        Method for getting private key from file system
	        Need to convert private key to pkcs8 format in order to read them in java
	        Keys need to be in der format
	     */
	    public PrivateKey getPrivateKey(String filename) throws IOException,
	            NoSuchAlgorithmException, InvalidKeySpecException {

	        File file = new File(filename);
	        DataInputStream dis = new DataInputStream(new FileInputStream(file));
	        byte[] privKey = new byte[(int) file.length()];
	        dis.readFully(privKey);
	        dis.close();

	        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privKey);
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        return keyFactory.generatePrivate(spec);

	    }

	    /*
	        Method for getting private key from file system
	        Need to convert public key to X509 format in order to read them in java
	        Keys need to be in der format
	     */
	    public PublicKey getPublicKey(String filename) throws IOException,
	            NoSuchAlgorithmException, InvalidKeySpecException {

	        File file = new File(filename);
	        DataInputStream dis = new DataInputStream(new FileInputStream(file));
	        byte[] pubKey = new byte[(int) file.length()];
	        dis.readFully(pubKey);
	        dis.close();

	        X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKey);
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        return keyFactory.generatePublic(spec);

	    }

	    /*
	        Method for symmetric encription of file
	     */
	    public byte[] SymmetricFileEncryption(byte[] file, SecretKey key)
	            throws InvalidKeyException, IllegalBlockSizeException,
	            BadPaddingException {

	        this.symmCipher.init(Cipher.ENCRYPT_MODE, key);
	        return this.symmCipher.doFinal(file);
	    }

	    /*
	        Method for symmetric decription of file
	     */
	    public byte[] SymmetricFileDecription(byte[] file, SecretKey key)
	            throws InvalidKeyException, IllegalBlockSizeException,
	            BadPaddingException {
	        this.symmCipher.init(Cipher.DECRYPT_MODE, key);
	        return this.symmCipher.doFinal(file);
	    }

	    /*
	        Method for asymmetric encription of file
	     */
	    public byte[] AsymmetricFileEncription(byte[] file, PublicKey pubKey)
	            throws IOException, GeneralSecurityException {
	        this.asymmCipher.init(Cipher.ENCRYPT_MODE, pubKey);
	        return this.asymmCipher.doFinal(file);
	    }

	    /*
	        Method for asymmetric decription of file
	     */
	    public byte[] AsymmetricFileDecription(byte[] file, PrivateKey privKey)
	            throws IOException, GeneralSecurityException {
	        this.asymmCipher.init(Cipher.DECRYPT_MODE, privKey);
	        return this.asymmCipher.doFinal(file);
	    }

	    /*
	        Method for write encrypted file
	     */
	    public void writeToFile(File file, byte[] data) throws IOException,
	            IllegalBlockSizeException, BadPaddingException {

	        FileOutputStream fos = new FileOutputStream(file);

	        byte[] output = this.symmCipher.doFinal(data);

	        fos.write(output);
	        fos.flush();
	        fos.close();
	    }

	    /*
	        Method for string (message) encryption with symmetric algorithm
	     */
	    public String EncryptStringSymmetric(String message, SecretKey key)
	            throws InvalidKeyException, IllegalBlockSizeException,
	            BadPaddingException {

	        String encryptedData = null;
	        this.symmCipher.init(Cipher.ENCRYPT_MODE, key);
	        final byte[] encryptedDataBytes = symmCipher.doFinal(message.getBytes());
	        encryptedData = new BASE64Encoder().encode(encryptedDataBytes);

	        return encryptedData;
	    }

	    /*
	        Method for decription of string (message)encrypted with symmetric algorithm
	     */
	    public String DecryptStringSymmetric(String message, SecretKey key)
	            throws InvalidKeyException, IllegalBlockSizeException,
	            BadPaddingException, IOException {

	        String decryptedData = null;

	        this.symmCipher.init(Cipher.DECRYPT_MODE, key);
	        final byte[] decryptedDataBytes = symmCipher.doFinal(new BASE64Decoder().decodeBuffer(message));
	        decryptedData = new String(decryptedDataBytes);

	        return decryptedData;
	    }

	    public String EncryptStringAsymmetric(String message, PrivateKey key)
	            throws InvalidKeyException, IllegalBlockSizeException,
	            BadPaddingException {
	        
	        this.asymmCipher.init(Cipher.ENCRYPT_MODE, key);
	        return Base64.getEncoder().encodeToString(asymmCipher.doFinal(message.getBytes()));
	    }

	    public String DecryptStringAsymmetric(String encMessage, PublicKey key) 
	            throws InvalidKeyException, IllegalBlockSizeException, 
	            BadPaddingException {
	        this.asymmCipher.init(Cipher.DECRYPT_MODE, key);
	        return new String(asymmCipher.doFinal(Base64.getDecoder().decode(encMessage)));
	    }

	    public X509Certificate getCertificate(String path) throws CertificateException,
	            FileNotFoundException {

	        X509Certificate certificate = null;

	        CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        FileInputStream fis = new FileInputStream(path);
	        certificate = (X509Certificate) cf.generateCertificate(fis);

	        return certificate;
	    }
}
