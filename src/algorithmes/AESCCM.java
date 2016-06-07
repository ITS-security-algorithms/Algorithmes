package algorithmes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class AESCCM {
    
    public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        
        //Message à chiffrer
        String message = "Hello world";
        System.out.println("Message à chiffer : \n" + message +"\n\nValeur hexadécimale :\n"+Hex.toHexString(message.getBytes())+"\n"+message.getBytes().length+" octets");
            
        //Security provider
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Security.addProvider(bc);
            
        //Générateur de clés AES 128 bits
        KeyGenerator keygen = KeyGenerator.getInstance("AES","BC");
        keygen.init(128);
        
        //Génération de la clé de chiffrement AES
        SecretKey secretKey = keygen.generateKey();
        System.out.println("\nClé de chiffrement :\n"+Hex.toHexString(secretKey.getEncoded())+"\n"+secretKey.getEncoded().length+" octets");
            
        //Generates d'un random nonce de 12 octets
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        System.out.println("\nNonce :\n"+Hex.toHexString(nonce)+"\n"+nonce.length+" octets");
            
        //Création de l'objet Cipher et des paramètres de l'algorithme
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding",bc);
        AlgorithmParameterSpec params = new GCMParameterSpec(16 * 8,nonce);
            
        //Initilisation du cipher pour chiffrement
        cipher.init(Cipher.ENCRYPT_MODE,secretKey, params);
            
        //Chiffrement
        byte[] cipherText = cipher.doFinal(message.getBytes());
        System.out.println("\nMessage chiffré :\n"+Hex.toHexString(cipherText)+"\n"+cipherText.length+" octets");
        
        //Initialisation du cipher pour déchiffrement
        cipher.init(Cipher.DECRYPT_MODE,secretKey, params);
            
        //Déchiffrement:
        byte[] decryptedMessage = cipher.doFinal(cipherText);
        System.out.println("\nMessage dechiffré: \n"+new String(decryptedMessage, "UTF-8")+" \nValeur hexadécimale : "+ Hex.toHexString(decryptedMessage) +"\n"+decryptedMessage.length+" octets");

    }
}