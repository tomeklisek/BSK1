/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1.Serpent;

import bsk1.Log;
import bsk1.RSA.RSADecryption;
import bsk1.User;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import sun.misc.BASE64Decoder;

/**
 *
 * @author bln
 */
public class Decryption {
    private int dlugosc_klucza = 0, dlugosc_podbloku = 0;
    private String tryb_szyfrowania;
    private byte[] iv, wiadomosc;
    public boolean wasAlgorithmLoaded = false;
    
    private HashMap<String, String> users = new HashMap<String, String>();

    // klucz z hasła
    private static byte[] passwordToKey(byte[] haslo) throws NoSuchAlgorithmException {
	final MessageDigest dig;
	dig = MessageDigest.getInstance("SHA-256");
        dig.update(haslo);
	return dig.digest();
    }

    // deszyfrowanie pliku
    private byte[] decipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
        int minSize = cipher.getOutputSize(data.length);
        byte[] outBuf = new byte[minSize];

        int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        int length2 = 0;
        try{ 
            length2 = cipher.doFinal(outBuf, length1);
        }
        catch(DataLengthException | IllegalStateException | InvalidCipherTextException ex){
        }
        
        int sumLength = length1 + length2;
        byte[] result = new byte[sumLength];
        System.arraycopy(outBuf, 0, result, 0, result.length);
        return result;
    }    

    // deszyfrowanie klucza hasłem
    public static byte[] decryptKeyWithPassword(byte[] kluczSesyjny, String haslo) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedEncodingException {
        byte[] kluczHasloBytes = passwordToKey(haslo.getBytes("UTF-8"));
	byte[] kluczHaslo = new SecretKeySpec(kluczHasloBytes, "Serpent").getEncoded();
	
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SerpentEngine(), new PKCS7Padding());
	cipher.init(false, new KeyParameter(kluczHaslo));
        
        byte[] output = new byte[cipher.getOutputSize(kluczSesyjny.length)];
	int outputLength1 = cipher.processBytes(kluczSesyjny, 0, kluczSesyjny.length, output, 0);
	int outputLength2 = 0;
        try{
            outputLength2 = cipher.doFinal(output, outputLength1);
        }
        catch(DataLengthException | IllegalStateException | InvalidCipherTextException ex){
        }
        
        byte[] result = new byte[outputLength1 + outputLength2];
        System.arraycopy(output, 0, result, 0, result.length);
	return result;
    }
    
    // odczyt zawartości pliku
    private void readXML(File plik_wejsciowy) throws FileNotFoundException, IOException{
        int nline = 0;
        int bytesRead = 0;
        boolean wasHeaderLoaded = false;
        boolean wasUsersStarted = false;
        boolean isUserLoading = false;
        boolean keyStarted = false;
        BASE64Decoder decoder = new BASE64Decoder();
        
        if (plik_wejsciowy.isDirectory() == true) {
            Log.writeLine("Błąd: wskazana pozycja pliku wejściowego jest katalogiem!");
            return;
        }

        String user = null, key = null;
        
        FileInputStream fstream = new FileInputStream(plik_wejsciowy);
        DataInputStream in = new DataInputStream(fstream);
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        String strLine;
        
        while ((strLine = br.readLine()) != null) {
                if (wasHeaderLoaded == false) {
                    bytesRead += strLine.getBytes().length + 1; // + \n
                
                    strLine = strLine.trim();

                    if (nline == 0) {
                        if (!"<FileHeader>".equals(strLine)) {
                            Log.writeLine("Błąd: Nieprawidłowy nagłówek pliku!");
                            break;
                        }
                    } else {
                        // Algorithm
                        if ("<Algorithm>Serpent</Algorithm>".equals(strLine)) {
                            wasAlgorithmLoaded = true;
                            continue;
                        }

                        // CipherMode
                        if (strLine.indexOf("<CipherMode>") != -1 && strLine.indexOf("</CipherMode>") != -1) {
                                strLine = strLine.replaceAll("<CipherMode>", "");
                                strLine = strLine.replaceAll("</CipherMode>", "");
                                if (!"ECB".equals(strLine) && !"CBC".equals(strLine) 
                                        && !"OFB".equals(strLine) && !"CFB".equals(strLine)) {
                                    Log.writeLine("Błąd: Nieobsługiwany tryb szyfrowania!");
                                    break;
                                }
                                tryb_szyfrowania = strLine;
                                continue;
                        }

                        // SegmentSize
                        if (strLine.indexOf("<SegmentSize>") != -1 && strLine.indexOf("</SegmentSize>") != -1) {
                                strLine = strLine.replaceAll("<SegmentSize>", "");
                                strLine = strLine.replaceAll("</SegmentSize>", "");
                                if (!"8".equals(strLine) && !"16".equals(strLine) && !"32".equals(strLine) && !"64".equals(strLine)) {
                                    Log.writeLine("Błąd: Nieobsługiwany rozmiar podbloku!");
                                    break;
                                }
                                dlugosc_podbloku = Integer.parseInt(strLine);
                                continue;
                        }

                        // KeySize
                        if (strLine.indexOf("<KeySize>") != -1 && strLine.indexOf("</KeySize>") != -1) {
                                strLine = strLine.replaceAll("<KeySize>", "");
                                strLine = strLine.replaceAll("</KeySize>", "");
                                // 128, 192, 256
                                if (!"128".equals(strLine) && !"192".equals(strLine) && !"256".equals(strLine)) {                                    
                                    Log.writeLine("Błąd: Nieobsługiwany rozmiar klucza!");
                                    break;
                                }
                                dlugosc_klucza = Integer.parseInt(strLine);
                                continue;
                        }

                        // IV
                        if (strLine.indexOf("<IV>") != -1 && strLine.indexOf("</IV>") != -1) {
                            strLine = strLine.replaceAll("<IV>", "");
                            strLine = strLine.replaceAll("</IV>", "");
                            iv = decoder.decodeBuffer(strLine);
                            continue;
                        }
                        
                        // Users
                        if (strLine.indexOf("<Users>") != -1) {
                            wasUsersStarted = true;
                            continue;
                        }
                        
                        if (strLine.indexOf("</Users>") != -1) {
                            wasUsersStarted = false;
                            continue;
                        }
                        
                        // User
                        if(wasUsersStarted == true && strLine.indexOf("<User>") != -1) {
                            isUserLoading = true;
                            bytesRead += 3;
                            continue;
                        }
                        if(wasUsersStarted == true && strLine.indexOf("</User>") != -1) {
                            isUserLoading = false;
                            users.put(user, key.trim());
                            continue;
                        }
                        
                        // User -> Name
                        if (strLine.indexOf("<Name>") != -1 && strLine.indexOf("</Name>") != -1) {
                            strLine = strLine.replaceAll("<Name>", "");
                            strLine = strLine.replaceAll("</Name>", "");
                            user = strLine;
                            continue;
                        }
                        
                        // User -> SessionKey
                        if (strLine.indexOf("<SessionKey>") != -1) {
                            strLine = strLine.replaceAll("<SessionKey>", "");
                            key = strLine;
                            key += "\n";
                            keyStarted = true;
                            continue;
                        }
                        if (strLine.indexOf("</SessionKey>") != -1) {
                            strLine = strLine.replaceAll("</SessionKey>", "");
                            key += strLine;
                            keyStarted = false;
                            continue;
                        }
                        if (keyStarted == true) {
                            key += strLine;
                            key += "\n";
                            continue;
                        }

                        // FileHeader - end
                        if (wasHeaderLoaded == false && strLine.indexOf("</FileHeader>") != -1) {
                            wasHeaderLoaded = true;
                        }
                    }
                }
                
                if (wasHeaderLoaded == true) {
                    break;
                }
                
                nline++;
            }
            
            br.close();
            in.close();
            fstream.close();
            
            fstream = new FileInputStream(plik_wejsciowy);
            in = new DataInputStream(fstream);
            
            int encryptedDataLength = (int) (plik_wejsciowy.length() - bytesRead);
            byte[] encrypted_data = new byte[encryptedDataLength]; 
            in.skipBytes(bytesRead);
            in.read(encrypted_data, 0, encryptedDataLength);
            in.close();  
            
            wiadomosc = encrypted_data;
    }
    
    // dekrypcja
    public void decrypt(File plik_wejsciowy, File plik_wyjsciowy, String user, String haslo, String privateKeyPath) throws Exception {
        if (users.containsKey(user))
            Log.writeLine("Start dekrypcji");
        
        long startTime = System.currentTimeMillis();
        
        // odczytanie pliku wejsciowego
        readXML(plik_wejsciowy);
        
        if (users.containsKey(user) && wasAlgorithmLoaded) {
            PaddedBufferedBlockCipher decryption = null;
            byte[] ivByte = iv;

            RSADecryption rsaDec = new RSADecryption();
            byte[] keyByte = rsaDec.decrypt(privateKeyPath, users.get(user), haslo);
            byte[] outputByte = null;
            KeyParameter kpECB = null;
            
            try {
                kpECB = new KeyParameter(keyByte);
            } catch(NullPointerException ex) {
                return;
            }

            CipherParameters ivAndKeyECB = new ParametersWithIV(kpECB, ivByte);

            switch (tryb_szyfrowania) {
                case "ECB":
                    decryption = new PaddedBufferedBlockCipher(new SerpentEngine(), new PKCS7Padding());
                    decryption.init(false, kpECB);
                    outputByte = decipherData(decryption, wiadomosc);
                    break;
                case "CBC":
                    decryption = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SerpentEngine()), new PKCS7Padding());
                    decryption.init(false, ivAndKeyECB);
                    outputByte = decipherData(decryption, wiadomosc);
                    break;
                case "CFB":
                    decryption = new PaddedBufferedBlockCipher(new CFBBlockCipher(new SerpentEngine(), dlugosc_podbloku), new PKCS7Padding());
                    decryption.init(false, ivAndKeyECB);
                    outputByte = decipherData(decryption, wiadomosc);
                    break;
                case "OFB":
                    decryption = new PaddedBufferedBlockCipher(new OFBBlockCipher(new SerpentEngine(), dlugosc_podbloku), new PKCS7Padding());
                    decryption.init(false, ivAndKeyECB);
                    outputByte = decipherData(decryption, wiadomosc);
                    break;
            }

            try (FileOutputStream fos = new FileOutputStream(plik_wyjsciowy)) {
                fos.write(outputByte);
            } catch(Exception e) {
                Log.writeLine("Błąd: Nie mogę zapisać wyniku do pliku!");
            }
            
            long endTime = System.currentTimeMillis() - startTime;
            float seconds = endTime / 1000.0f;
            Log.writeLine("Dekrypcja zajęła: " + seconds + "sekund.");
            Log.writeLine("Koniec dekrypcji");
            JOptionPane.showMessageDialog(null, "Zakończono dekrypcję!", "Informacja", JOptionPane.INFORMATION_MESSAGE);
        } else {
            Log.writeLine("Błąd: Podany user nie istnieje!");
        }
    }
}