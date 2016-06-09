/*************************************************************************
*                                                                        *
*  Télécom ParisTech, Département INFRES,                                *
*  Team Securité des Réseaux,                                            *
*  URL: "https://www.telecom-paristech.fr"                               *
*                                                                        *
*************************************************************************/
/**
 * @author Eduardo Sallés Daniel, eduardo.sallesdaniel@telecom-paristech.fr
 * @author Julien Huor, julien.huor@gmail.com
 * @author Jean-Philippe, monteuuis@telecom-paristech.fr
 */
package algorithmes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class ECDSA {
    public static void main(String args[]) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException, IOException{
        
        //Message à signer
        String message = "Hello World";
        System.out.println("Message à signer : " + message + "\nValeur héxadécimale : "+Hex.toHexString(message.getBytes())+" "+message.getBytes().length+" octets");
            
        //Security provider
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Security.addProvider(bc);
        
        //Initialisation du haché avec SHA-256
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256",bc);
        sha256Digest.update(message.getBytes());
        byte[] messageDigest = sha256Digest.digest();
        System.out.println("\nMessage haché :\n"+Hex.toHexString(messageDigest)+"\n"+messageDigest.length+" octets");
            
        
        //Générateur de paire de clé
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", bc);
        
        //Initialisation avec la courbe P-256
        kpg.initialize(ECNamedCurveTable.getParameterSpec("P-256"), new SecureRandom());
        
        //Generation de la paire de clé ECDSA
        KeyPair keys = kpg.generateKeyPair();
        System.out.println("\nClé publique :\n"+"  "+keys.getPublic());
        System.out.println("Clé privée :\n"+"  "+keys.getPrivate());
            
        //Signature ECDSA avec SHA-256
        java.security.Signature signature = java.security.Signature.getInstance("NONEwithECDSA", bc); 
        signature.initSign(keys.getPrivate());
        signature.update(messageDigest);
        
        //signature en DER
        byte[] signatureDER = signature.sign();
        System.out.println("Signature DER encodé :\n"+Hex.toHexString(signatureDER));
            
        //Décomposition de l'encodage DER en deux entiers r et s
        ByteArrayInputStream inStream = new ByteArrayInputStream(signatureDER);
        ASN1InputStream asn1InputStream = new ASN1InputStream(inStream);
        DLSequence dLSequence = (DLSequence) asn1InputStream.readObject();
        asn1InputStream.close();
        BigInteger r = ((ASN1Integer) dLSequence.getObjectAt(0)).getPositiveValue();
        System.out.println("\nR (Hexadecimal) :\n"+r.toString(16)+"\n"+r.toString(16).length()/2+" octets");
        BigInteger s = ((ASN1Integer) dLSequence.getObjectAt(1)).getPositiveValue();
        System.out.println("\nS (Hexadecimal) :\n"+s.toString(16)+"\n"+s.toString(16).length()/2+" octets");
            
        //Verification de la signature ECDSA
        sha256Digest.update(message.getBytes()); 
        messageDigest = sha256Digest.digest();//haché du message à vérifier
        
        Signature sig = Signature.getInstance("NONEwithECDSA", bc); 
        sig.initVerify(keys.getPublic()); //clé public associé à la paire de clé qui a signer le message
        sig.update(messageDigest); //haché calculé
        
        //Vérification du message
        boolean verify = sig.verify(signatureDER);
        System.out.println("\nLa signature est-elle valide ?\n"+verify);
    }
}
