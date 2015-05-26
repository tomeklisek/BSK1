/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1.RSA;

import java.io.BufferedReader;
import java.io.FileReader;
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

/**
 *
 * @author bln
 */
public class test {
    public static void main(String[] args) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException, Exception
    {
        String publicKeyFilename = "D:\\studia\\studia\\sem6\\BSK\\proj1\\BSK\\Projekt - Rafał Ludwiczak\\RSA keys\\pub.key";
        String privateKeyFilename = "D:\\studia\\studia\\sem6\\BSK\\proj1\\BSK\\Projekt - Rafał Ludwiczak\\RSA keys\\priv.key";
        String password = "qwerty";
        String inputData = "dfsdfs";
        //String outputData = null;
        
        //generate keys
        GenerateRSAKeys gen = new GenerateRSAKeys();
        gen.generate(publicKeyFilename, privateKeyFilename, password);
        
        RSAEncryption rsaEncryption = new RSAEncryption();
        
        System.out.println("B: " + inputData);
        
        byte[] input = inputData.getBytes();
        
        String encrypted = rsaEncryption.encrypt(publicKeyFilename, input);
        System.out.println("E: " + encrypted);
        
        RSADecryption rsaDecryption = new RSADecryption();
        byte[] output = rsaDecryption.decrypt(privateKeyFilename, encrypted, password);
        String decrypted = new String(output);
        System.out.println("D: " + decrypted);
    }
}
