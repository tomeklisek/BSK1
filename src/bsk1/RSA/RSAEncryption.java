/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1.RSA;

import bsk1.MainWindow;
import java.io.*;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class RSAEncryption {
    public String encrypt(String publicKeyFilename, byte[] inputData){

        String encryptedData = null;
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            BASE64Decoder b64 = new BASE64Decoder();
            RSAFileHelper fh = new RSAFileHelper();
            String key = fh.readPubKeyFromFile(publicKeyFilename);
            AsymmetricKeyParameter publicKey = 
                (AsymmetricKeyParameter) PublicKeyFactory.createKey(b64.decodeBuffer(key));
            AsymmetricBlockCipher e = new RSAEngine();
            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
            e.init(true, publicKey);

            byte[] hexEncodedCipher = e.processBlock(inputData, 0, inputData.length);

            BASE64Encoder b64e = new BASE64Encoder();
            encryptedData = b64e.encodeBuffer(hexEncodedCipher);
        }
        catch (IOException | InvalidCipherTextException ex) {
            Logger.getLogger(MainWindow.class.getName()).log(Level.SEVERE, null, ex);
        }
       
        return encryptedData;
    }
}