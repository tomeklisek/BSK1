/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1.RSA;

import bsk1.Log;
import java.awt.MouseInfo;
import java.awt.Point;
import java.awt.PointerInfo;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import sun.misc.BASE64Encoder;

/**
 *
 * @author bln
 */
public class GenerateRSAKeys {
    public void generate(String publicKeyFilename, String privateFilename, String password) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException {
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
            BASE64Encoder b64 = new BASE64Encoder();

            PointerInfo pointerInfo = MouseInfo.getPointerInfo();
            Point point = pointerInfo.getLocation();
            long pointerPosition = ((long) point.getX()) * ((long) point.getY());

            long seed = Runtime.getRuntime().freeMemory() ^ pointerPosition
                    ^ System.nanoTime() ^ System.currentTimeMillis();

            SecureRandom random = new SecureRandom(Long.toHexString(seed).getBytes("UTF-8"));
            generator.initialize(1024, random);

            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            Key privKey = pair.getPrivate();

            
            RSAFileHelper fh = new RSAFileHelper();
            fh.writePubKeyToFile(publicKeyFilename, b64.encode(pubKey.getEncoded()));

            try {
                fh.writePrvKeyToFile(privateFilename, b64.encode(encryptKeyWithPassword(privKey.getEncoded(), password)));
//                fh.writePrvKeyToFile(privateFilename, b64.encode(privKey.getEncoded()));
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
                    
        } catch (NoSuchAlgorithmException | NoSuchProviderException | IOException e) {
            
        }
//        catch (InvalidKeySpecException ex) {
//            Logger.getLogger(GenerateRSAKeys.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (NoSuchPaddingException ex) {
//            Logger.getLogger(GenerateRSAKeys.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (InvalidKeyException ex) {
//            Logger.getLogger(GenerateRSAKeys.class.getName()).log(Level.SEVERE, null, ex);
//        }
    }
    
    // skrót(klucz) z hasla
    private static byte[] getSHA256Hash(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest dig;
	dig = MessageDigest.getInstance("SHA-256");
        dig.update(content);
	return dig.digest();
    }
    
    // szyfrowanie klucza hasłem
    public static byte[] encryptKeyWithPassword(byte[] klucz, String haslo) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        
        try {
            //char[] passChars = jPasswordField1.getPassword();
            byte[] salt = new String("12345678").getBytes();
            int iterationCount = 20;
            int keyStrength = 256;
            
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            KeySpec pbeKeySpec = new PBEKeySpec(haslo.toCharArray(),salt,iterationCount,keyStrength);
            SecretKey tmp = factory.generateSecret(pbeKeySpec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
            
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secret);
            
            byte[] privateKeyBytes = klucz;
            
            byte[] privateKeyEnc = cipher.doFinal(privateKeyBytes);
            
            return privateKeyEnc;
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(GenerateRSAKeys.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(GenerateRSAKeys.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return klucz;
    }
    /*
    public static byte[] encryptKeyWithPassword(byte[] klucz, String haslo) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedEncodingException {
        byte[] keyPassBytes = getSHA256Hash(haslo.getBytes("UTF-8"));
	byte[] keyPass = new SecretKeySpec(keyPassBytes, "Serpent").getEncoded();
        
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SerpentEngine(), new PKCS7Padding());
	cipher.init(true, new KeyParameter(keyPass));
        
        byte[] output = new byte[cipher.getOutputSize(klucz.length)];
	int outputLength1 = cipher.processBytes(klucz, 0, klucz.length, output, 0);
	int outputLength2 = cipher.doFinal(output, outputLength1);
        
        byte[] result = new byte[outputLength1 + outputLength2];
        System.arraycopy(output, 0, result, 0, result.length);
	return result;
    } */
}
