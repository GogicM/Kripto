package crypto;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.Signature;
import java.security.SignatureException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Crypto {

    private Cipher asymmCipher;
    //one cipher for asymmetric and one for symmetric
    private Cipher symmCipher;

    public IvParameterSpec iv;
    SecureRandom sr;
    KeyGenerator kg;

    public Crypto() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.asymmCipher = Cipher.getInstance("RSA");
        // this.asymmCipher.init(keylength);
        //Changed from CBC to ECB, had problems with iv for CBC
        this.symmCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //this.symmCipher = Cipher.getInstance("AES/ECB/NoPadding");

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
            BadPaddingException, NoSuchAlgorithmException {

//	    	sr = SecureRandom.getInstance("SHA1PRNG");
//	    	kg = KeyGenerator.getInstance("AES");
//	    	kg.init(128, sr);
        this.symmCipher.init(Cipher.ENCRYPT_MODE, key);
        // Crypto.iv = new IvParameterSpec(this.symmCipher.getIV());
        //   iv = new IvParameterSpec(this.symmCipher.getIV());

        return this.symmCipher.doFinal(file);
    }

    /*
	        Method for symmetric decription of file
     */
    public byte[] SymmetricFileDecription(byte[] file, SecretKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        //System.out.println("IV : " + this.iv);
//	        try {
//				Thread.currentThread().sleep(3000);
//			} catch (InterruptedException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
        this.symmCipher.init(Cipher.DECRYPT_MODE, key);
        return this.symmCipher.doFinal(file);
    }

    /*
	        Method for asymmetric encription of file
     */
    public byte[] AsymmetricFileEncription(byte[] file, PublicKey pubKey)
            throws IOException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

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
//	    public void writeToFile(File file, byte[] data, SecretKey key) throws IOException,
//	            IllegalBlockSizeException, BadPaddingException, 
//	            InvalidKeyException {
//
//	        FileOutputStream fos = new FileOutputStream(file, false);
//	        this.symmCipher.init(Cipher.ENCRYPT_MODE, key);
//	        byte[] output = this.symmCipher.doFinal(data);
//
//	        fos.write(output);
//	        fos.flush();
//	        fos.close();
//	    }
    public void writeToFile(File output, byte[] data, SecretKey key)
            throws IllegalBlockSizeException, BadPaddingException, 
            IOException, InvalidKeyException, NoSuchAlgorithmException {
        
        FileOutputStream fos = new FileOutputStream(output);
        byte[] encContent = SymmetricFileEncryption(data, key);
        fos.write(data);
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
       // final byte[] encryptedDataBytes = symmCipher.doFinal(message.getBytes());
       // encryptedData = new BASE64Encoder().encode(encryptedDataBytes);

    //    return encryptedData;
            return Base64.getEncoder().encodeToString(symmCipher.doFinal(message.getBytes()));

    }

    /*
	        Method for decription of string (message)encrypted with symmetric algorithm
     */
    public String DecryptStringSymmetric(String message, SecretKey key)
            throws InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, IOException {

        String decryptedData = null;

        this.symmCipher.init(Cipher.DECRYPT_MODE, key);
//        final byte[] decryptedDataBytes = symmCipher.doFinal(new BASE64Decoder().decodeBuffer(message));
//        decryptedData = new String(decryptedDataBytes);
//
//        return decryptedData;
          return new String(symmCipher.doFinal(Base64.getDecoder().decode(message)));
    }
    
    /*
    	Method for string array  encryption with symmetric algorithm
    */
    public String[] EncryptStringArraySymmetric(String[] array, SecretKey key)
    		throws InvalidKeyException, IllegalBlockSizeException,
    		BadPaddingException {
    	
    	if(array == null) {
    		System.out.println("ARRAY IS NULL");
    	}
    	String[] encryptedArray = new String[array.length];
    	this.symmCipher.init(Cipher.ENCRYPT_MODE, key);
    	// final byte[] encryptedDataBytes = symmCipher.doFinal(message.getBytes());
    	// encryptedData = new BASE64Encoder().encode(encryptedDataBytes);

    	//    return encryptedData;
    	for(int i = 0; i < array.length; i++) {
    		encryptedArray[i] = Base64.getEncoder().encodeToString(symmCipher.doFinal(array[i].getBytes()));
    	}
    	return encryptedArray;

    }

	/*
	    Method for decription of string array encrypted with symmetric algorithm
	*/
	public String[] DecryptStringArraySymmetric(String[] encryptedArray, SecretKey key)
	    throws InvalidKeyException, IllegalBlockSizeException,
	    BadPaddingException, IOException {
	
		String[] decryptedArray = new String[encryptedArray.length];
		
		this.symmCipher.init(Cipher.DECRYPT_MODE, key);
		//final byte[] decryptedDataBytes = symmCipher.doFinal(new BASE64Decoder().decodeBuffer(message));
		//decryptedData = new String(decryptedDataBytes);
		//
		//return decryptedData;
		for(int i = 0; i < encryptedArray.length; i++) {
			decryptedArray[i] = new String(symmCipher.doFinal(Base64.getDecoder().decode(encryptedArray[i])));
		}
		return decryptedArray;
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

    public String encodeWithSHA256(String message) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        String encoded = Base64.getEncoder().encodeToString(hash);

        return encoded;
    }

    public byte[] signMessagge(String message, PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, InvalidKeySpecException, IOException, SignatureException {

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privateKey);
        sig.update(message.getBytes());
        return sig.sign();

    }

    public boolean verifyDigitalSignature(byte[] data, byte[] signature, PublicKey publicKey)
            throws GeneralSecurityException, IOException {

        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
