/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1.Serpent;

import bsk1.RSA.RSAEncryption;
import bsk1.User;
import java.awt.MouseInfo;
import java.awt.Point;
import java.awt.PointerInfo;
import java.io.*;
import java.security.*;
import java.util.Dictionary;
import java.util.HashMap;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Encoder;

/**
 *
 * @author bln
 */
public class Encryption {
    
    // IV dla Serpent
    private byte[] createIV() throws UnsupportedEncodingException {
        PointerInfo pointerInfo = MouseInfo.getPointerInfo();
        Point point = pointerInfo.getLocation();
        long pointerPosition = ((long) point.getX()) * ((long) point.getY());

        long seed = Runtime.getRuntime().freeMemory() ^ pointerPosition
                ^ System.nanoTime() ^ System.currentTimeMillis();

        SecureRandom random = new SecureRandom(Long.toHexString(seed).getBytes("UTF-8"));

        byte[] createdIV = new byte[16];
        random.nextBytes(createdIV);
        return createdIV;
    }
    
    // klucz Serpent
    private Key createKey(int keyLength) throws NoSuchAlgorithmException {
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
	int outputLength1 = cipher.processBytes(kluczSesyjny, 0, kluczSesyjny.length, output, 0);
	int outputLength2 = cipher.doFinal(output, outputLength1);
        
        byte[] result = new byte[outputLength1 + outputLength2];
        System.arraycopy(output, 0, result, 0, result.length);
	return result;
    }
    
    // szyfrowanie danych
    private byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
        int minSize = cipher.getOutputSize(data.length);
        byte[] outBuf = new byte[minSize];
        int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        int length2 = cipher.doFinal(outBuf, length1);
        int actualLength = length1 + length2;
        byte[] result = new byte[actualLength];
        System.arraycopy(outBuf, 0, result, 0, result.length);
        return result;
    }
    
    // zawartość pliku
    private void createResultFile(File plik_wyjsciowy, int keysize, int subblock, String mode,
            byte[] key, byte[] iv, byte[] data, HashMap<String, User> users) throws FileNotFoundException, IOException {
        String s;
        
        RSAEncryption rsaEnc = new RSAEncryption();
        
        s = "<FileHeader>\n";
        s += "<Algorithm>Serpent</Algorithm>\n";
        s += "<CipherMode>" + mode + "</CipherMode>\n";
        s += "<SegmentSize>" + subblock + "</SegmentSize>\n";
        s += "<KeySize>" + keysize + "</KeySize>\n";
        s += "<IV>" + new String(Base64.encode(iv)) + "</IV>\n";
        s += "<Padding>PKCS7Padding</Padding>\n";
        s += "<Users>\n";
        for (User us : users.values()) {
                s += "<User>\n";
                s += "<Name>" + us.username + "</Name>\n";
                s += "<SessionKey>" + rsaEnc.encrypt(us.pubKeyPath, key) + "</SessionKey>\n";
                s += "</User>\n";
            }
        s += "</Users>\n";
        s += "</FileHeader>\n";
        
        try (FileOutputStream fos = new FileOutputStream(plik_wyjsciowy); BufferedOutputStream bos = new BufferedOutputStream(fos)) {
            bos.write(s.getBytes());
            bos.write(data);
            bos.flush();
        }
    }
    
    // enkrypcja pliku
    public void encrypt(File plik_wejsciowy, File plik_wyjsciowy, int dlugosc_klucza, int dlugosc_podbloku, String tryb_dzialania, HashMap<String, User> users) throws Exception {
        byte[] buffer = new byte[(int)plik_wejsciowy.length()];
        System.out.println("buffer: "+buffer);
        try (DataInputStream in = new DataInputStream(new FileInputStream(plik_wejsciowy))) {
            in.readFully(buffer);
            System.out.println("in: "+in);
        }
        System.out.println("input: "+plik_wejsciowy);
        System.out.println("buffer: "+buffer);
        // parametry
        PaddedBufferedBlockCipher encryption = null;
        byte[] iv = createIV();
        byte[] klucz = createKey(dlugosc_klucza).getEncoded();
        byte[] wyjscie = null;

        KeyParameter kp = new KeyParameter(klucz);
        CipherParameters ivAndKey = new ParametersWithIV(kp, iv); 
        
         // rozne tryby dzialania algorytmu
        switch (tryb_dzialania) {
            case "ECB":
                encryption = new PaddedBufferedBlockCipher(new SerpentEngine(), new PKCS7Padding());
                encryption.init(true, kp);
                wyjscie = cipherData(encryption, buffer);
                createResultFile(plik_wyjsciowy, dlugosc_klucza, dlugosc_podbloku, tryb_dzialania, klucz, iv, wyjscie, users);
                break;
            case "CBC":
                encryption = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SerpentEngine()), new PKCS7Padding());
                encryption.init(true, ivAndKey);
                wyjscie = cipherData(encryption, buffer);                           
                createResultFile(plik_wyjsciowy, dlugosc_klucza, dlugosc_podbloku, tryb_dzialania, klucz, iv, wyjscie, users);
                break;
            case "CFB":
                encryption = new PaddedBufferedBlockCipher(new CFBBlockCipher(new SerpentEngine(), dlugosc_podbloku), new PKCS7Padding());
                encryption.init(true, ivAndKey);
                wyjscie = cipherData(encryption, buffer);                       
                createResultFile(plik_wyjsciowy, dlugosc_klucza, dlugosc_podbloku, tryb_dzialania, klucz, iv, wyjscie, users);
                break;
            case "OFB":
                encryption = new PaddedBufferedBlockCipher(new OFBBlockCipher(new SerpentEngine(), dlugosc_podbloku), new PKCS7Padding());
                encryption.init(true, ivAndKey);
                wyjscie = cipherData(encryption, buffer);
                createResultFile(plik_wyjsciowy, dlugosc_klucza, dlugosc_podbloku, tryb_dzialania, klucz, iv, wyjscie, users);
                break;
        }
    }
}
