/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package bsk1;

import bsk1.Serpent.Encryption;
import java.io.UnsupportedEncodingException;
import java.security.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 *
 * @author bln
 */
public class User {
    public String username;
    public String pubKeyPath;
    
    public User(String name, String pbkeypath) throws NoSuchAlgorithmException, NoSuchProviderException {
        username = name;
        pubKeyPath = pbkeypath;
    }
}
