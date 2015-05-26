/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1.RSA;

import bsk1.Log;
import bsk1.MainWindow;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
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

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author bln
 */
public class RSADecryption {
    public byte[] decrypt(String privateKeyFilename, String encryptedData, String password) throws Exception {
        //String outputData = null;
        byte[] hexEncodedCipher = null;
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            
            RSAFileHelper fh = new RSAFileHelper();
            
            String key = fh.readPrvKeyFromFile(privateKeyFilename);
            BASE64Decoder b64 = new BASE64Decoder();
            byte[] encryptedKey = b64.decodeBuffer(key);
            
//            byte[] decryptedKey = encryptedKey;
            byte[] decryptedKey = decryptKeyWithPassword(encryptedKey, password);
            
            AsymmetricKeyParameter privateKey = 
                (AsymmetricKeyParameter) PrivateKeyFactory.createKey(decryptedKey);
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(false, privateKey);
            
            byte[] messageBytes = b64.decodeBuffer(encryptedData);
            hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
        }
//        catch (IOException | NoSuchAlgorithmException | DataLengthException | IllegalStateException | IllegalArgumentException | InvalidCipherTextException ex) {
        catch (Exception ex)
        {
            Log.writeLine("Błąd: Nieprawidłowe hasło!");
            ex.printStackTrace();
            //Logger.getLogger(MainWindow.class.getName()).log(Level.SEVERE, null, ex);
        }
       
        return hexEncodedCipher;
    }
    
    // klucz z hasła
    private static byte[] passwordToKey(byte[] haslo) throws NoSuchAlgorithmException {
	final MessageDigest digester;
	digester = MessageDigest.getInstance("SHA-256");
        digester.update(haslo);
	return digester.digest();
    }

//    // deszyfrowanie klucza hasłem
//    public static byte[] decryptKeyWithPassword(byte[] klucz, String haslo) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedEncodingException {
//        byte[] kluczHasloBytes = passwordToKey(haslo.getBytes("UTF-8"));
//	byte[] kluczHaslo = new SecretKeySpec(kluczHasloBytes, "Serpent").getEncoded();
//	
//        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SerpentEngine(), new PKCS7Padding());
//	cipher.init(false, new KeyParameter(kluczHaslo));
//        
//        byte[] output = new byte[cipher.getOutputSize(klucz.length)];
//	int outputLength1 = cipher.processBytes(klucz, 0, klucz.length, output, 0);
//	int outputLength2 = 0;
//        
//        try{
//            outputLength2 = cipher.doFinal(output, outputLength1);
//        }
//        catch(DataLengthException | IllegalStateException | InvalidCipherTextException ex){
//            
//        }
//        
//        byte[] result = new byte[outputLength1 + outputLength2];
//        System.arraycopy(output, 0, result, 0, result.length);
//	return result;
//    }
    
    // deszyfrowanie klucza hasłem
    public static byte[] decryptKeyWithPassword(byte[] klucz, String haslo) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException {
        
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
            cipher.init(Cipher.DECRYPT_MODE, secret);
            
            byte[] privateKeyBytes = klucz;
            byte[] zero = new byte[] {0};
            ByteArrayOutputStream os;
            
            System.out.println("dlugosc klucza: "+privateKeyBytes.length);
            while (privateKeyBytes.length % 16 != 0)
            {
                System.out.println("dodaje 1..");
                os = new ByteArrayOutputStream();
                os.write(privateKeyBytes);
                os.write(zero);
                
                privateKeyBytes = os.toByteArray();
                System.out.println("dlugosc: "+privateKeyBytes.length);
            }
            
            byte[] privateKeyEnc = cipher.doFinal(privateKeyBytes);
            
            return privateKeyEnc;
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(GenerateRSAKeys.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(GenerateRSAKeys.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return klucz;
    }
}