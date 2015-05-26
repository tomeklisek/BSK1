/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1.RSA;

import java.io.*;

/**
 *
 * @author bln
 */
public class RSAFileHelper {
    public String readPrvKeyFromFile(String filepath) throws FileNotFoundException, IOException {
        String key = null;
        
        String strLine = null;
        int nol = 0; // line number
        boolean keyStarted = false;
        
        FileInputStream fstream = new FileInputStream(filepath);
        DataInputStream in = new DataInputStream(fstream);
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        
        while ((strLine = br.readLine()) != null) {
            strLine = strLine.trim();
 
            if (nol == 0) {
                if (!"<KeyHeader>".equals(strLine)) {
                    System.out.println("Nieprawidłowy nagłówek pliku klucza");
                    break;
                }
            } else {
                if(keyStarted == true) {
                    key += strLine;
                    key += "\n";
                }
                if (strLine.indexOf("<Key>") != -1) {
                    strLine = strLine.replaceAll("<Key>", "");
                    key = strLine;
                    key += "\n";
                    keyStarted = true;
                }
                if (strLine.indexOf("</Key>") != -1) {
                    strLine = strLine.replaceAll("</Key>", "");
                    key += strLine;
                    keyStarted = false;
                }
            }
            
            nol++;
        }
        
        br.close();
        in.close();
        fstream.close();
        
        return key;
    }
    
    public void writePrvKeyToFile(String filepath, String key) throws FileNotFoundException, IOException {
        try (FileOutputStream fos = new FileOutputStream(new File(filepath)); BufferedOutputStream bos = new BufferedOutputStream(fos)) {
            String keyFile = "<KeyHeader>\n<Algorithm>Serpent</Algorithm>\n<CipherMode>ECB</CipherMode>\n<Padding>PKCS7Padding</Padding>\n<Key>"+key+"</Key>\n</KeyHeader>";
            
            bos.write(keyFile.getBytes());
            bos.flush();
            System.out.println("zapisałem prv");
        }
    }

    String readPubKeyFromFile(String filepath) throws FileNotFoundException, IOException {
        String key = "";
        
        String strLine = null;
        
        FileInputStream fstream = new FileInputStream(filepath);
        DataInputStream in = new DataInputStream(fstream);
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        
        while ((strLine = br.readLine()) != null) {
            strLine = strLine.trim();

            key += strLine;
            key += "\n";

        }

        br.close();
        in.close();
        fstream.close();

        key = key.trim();
        
        return key;
    }

    void writePubKeyToFile(String filepath, String key) throws FileNotFoundException, IOException {
        try (FileOutputStream fos = new FileOutputStream(new File(filepath)); BufferedOutputStream bos = new BufferedOutputStream(fos)) {
            bos.write(key.getBytes());
            bos.flush();
            System.out.println("zapisałem pub");
        }
    }
    
}
