/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1.Serpent;

import bsk1.RSA.GenerateRSAKeys;
import bsk1.RSA.RSADecryption;
import bsk1.RSA.RSAEncryption;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
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
public class TestSerpentKeys {
    // klucz Serpent
    private static Key createKey(int keyLength) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("Serpent", new org.bouncycastle.jce.provider.BouncyCastleProvider());
        generator.init(keyLength);
        return generator.generateKey();
    }
    
    // skrót(klucz) z hasla
    private static byte[] getSHA256Hash(byte[] content) throws NoSuchAlgorithmException {
        MessageDigest dig;
	dig = MessageDigest.getInstance("SHA-256");
        dig.update(content);
	return dig.digest();
    }
    
    // szyfrowanie klucza hasłem
    public static byte[] encryptKeyWithPassword(byte[] kluczSesyjny, String haslo) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedEncodingException {
        byte[] kluczHasloBytes = getSHA256Hash(haslo.getBytes("UTF-8"));
	byte[] kluczHaslo = new SecretKeySpec(kluczHasloBytes, "Serpent").getEncoded();
        
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SerpentEngine(), new PKCS7Padding());
	cipher.init(true, new KeyParameter(kluczHaslo));
        
        byte[] output = new byte[cipher.getOutputSize(kluczSesyjny.length)];
	int outputLen1 = cipher.processBytes(kluczSesyjny, 0, kluczSesyjny.length, output, 0);
	int outputLen2 = cipher.doFinal(output, outputLen1);
        
        byte[] result = new byte[outputLen1 + outputLen2];
        System.arraycopy(output, 0, result, 0, result.length);
	return result;
    }
    
    // deszyfrowanie klucza hasłem
    public static byte[] decryptKeyWithPassword(byte[] klucz, String haslo) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedEncodingException {
        byte[] kluczHasloBytes = getSHA256Hash(haslo.getBytes("UTF-8"));
	byte[] kluczHaslo = new SecretKeySpec(kluczHasloBytes, "Serpent").getEncoded();
	
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SerpentEngine(), new PKCS7Padding());
	cipher.init(false, new KeyParameter(kluczHaslo));
        
        byte[] output = new byte[cipher.getOutputSize(klucz.length)];
	int outputLen1 = cipher.processBytes(klucz, 0, klucz.length, output, 0);
	int outputLen2 = 0;
        // na wypadek blednego hasla
        try{
            outputLen2 = cipher.doFinal(output, outputLen1);
        }
        catch(DataLengthException | IllegalStateException | InvalidCipherTextException ex){
            System.out.println("Blad w decryptKey!");
        }
        
        byte[] result = new byte[outputLen1 + outputLen2];
        System.arraycopy(output, 0, result, 0, result.length);
	return result;
    }
    
    public static void main(String[] args) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException, Exception
    {
        String publicKeyFilename = "C:\\Users\\bln\\Documents\\NetBeansProjects\\RSAtest\\testFiles\\pub.key";
        String privateKeyFilename = "C:\\Users\\bln\\Documents\\NetBeansProjects\\RSAtest\\testFiles\\priv.key";
        String password = "qwerty";
        
        BASE64Encoder b64 = new BASE64Encoder();
        
        //generate serpent key
        Key serpentKey = createKey(128);
        byte[] serpentKeyByte = serpentKey.getEncoded();//encryptKeyWithPassword(, password);
        String keyStr = b64.encode(serpentKeyByte);
        
        //generate RSA keys
        GenerateRSAKeys gen = new GenerateRSAKeys();
        gen.generate(publicKeyFilename, privateKeyFilename, password);
        
        RSAEncryption rsaEncryption = new RSAEncryption();
        
        System.out.println("B: " + keyStr);
        
        byte[] input = serpentKeyByte;
        
        String encrypted = rsaEncryption.encrypt(publicKeyFilename, input);
        System.out.println("E: " + encrypted);
        
        RSADecryption rsaDecryption = new RSADecryption();
        byte[] output = rsaDecryption.decrypt(privateKeyFilename, encrypted, password);
        String decrypted = b64.encode(output);
        System.out.println("D: " + decrypted);
    }
}
