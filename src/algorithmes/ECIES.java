package algorithmes;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

public class ECIES {
    
    public static void main(String args[]) throws UnsupportedEncodingException{
        
        //Message à chiffrer
        String message = "hello world";
        System.out.println("Message à chiffrer : " + message + "\nValeur héxadécimale : "+Hex.toHexString(message.getBytes())+" "+message.getBytes().length+" octets");
            
        //Générateur de clé asymétrique
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
            
        //Courbe elliptique utilisée : P-256 
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
            
        //Création des paramètres : Curve, G, N et H
        ECDomainParameters domainparams = new ECDomainParameters(ecSpec.getCurve(),ecSpec.getG(),ecSpec.getN(),ecSpec.getH());
        ECKeyGenerationParameters params = new ECKeyGenerationParameters(domainparams, new SecureRandom());
        
        //Initialisation du générateur de clé avec les paramètres spécifiés
        keyGen.init(params);
            
        //Génération paire de clé client  
        AsymmetricCipherKeyPair clientKeyPair = keyGen.generateKeyPair();
        System.out.println("\nClé publique client :\n     X: "+(((ECPublicKeyParameters)clientKeyPair.getPublic()).getQ()).getAffineXCoord()+"\n     "+
                (((ECPublicKeyParameters)clientKeyPair.getPublic()).getQ()).getAffineXCoord().getEncoded().length+" octets"+
                "\n     Y: "+ (((ECPublicKeyParameters)clientKeyPair.getPublic()).getQ()).getAffineYCoord()+"\n     "+
                (((ECPublicKeyParameters)clientKeyPair.getPublic()).getQ()).getAffineYCoord().getEncoded().length+" octets");
        System.out.println("\nClé privé client :\n     "+(((ECPrivateKeyParameters)clientKeyPair.getPrivate()).getD().toString(16))+"\n     "+
                ((ECPrivateKeyParameters)clientKeyPair.getPrivate()).getD().toString(16).length()/2+" octets");
            
        //Génération paire de clé client Serveur
        AsymmetricCipherKeyPair serverKeyPair = keyGen.generateKeyPair();
        System.out.println("\nClé public serveur :\n     X: "+(((ECPublicKeyParameters)serverKeyPair.getPublic()).getQ()).getAffineXCoord()+"\n     "+
                (((ECPublicKeyParameters)serverKeyPair.getPublic()).getQ()).getAffineXCoord().getEncoded().length+" octets"+
                "\n     Y: "+ (((ECPublicKeyParameters)serverKeyPair.getPublic()).getQ()).getAffineYCoord()+"\n     "+
                (((ECPublicKeyParameters)serverKeyPair.getPublic()).getQ()).getAffineYCoord().getEncoded().length+" octets");
        System.out.println("\nClé privé serveur :\n     "+(((ECPrivateKeyParameters)serverKeyPair.getPrivate()).getD().toString(16))+"\n     "+
                ((ECPrivateKeyParameters)serverKeyPair.getPrivate()).getD().toString(16).length()/2+" octets");
            
        System.out.println("*******************Chiffrement**********************");
        
        //Fonction KA
        //Création du secret partagé
        ECDHCBasicAgreement clientKeyAgree = new ECDHCBasicAgreement();
        clientKeyAgree.init(clientKeyPair.getPrivate());
        BigInteger clientSecret = clientKeyAgree.calculateAgreement(serverKeyPair.getPublic());
        byte[] kaSharedSecretEncryption = clientSecret.toByteArray();
        System.out.println("\nValeur du secret partagé: \n"+clientSecret.toString(16)+"\n"+clientSecret.toString(16).length()/2+" octets");
            
        //KDF2 avec SHA-256
        byte[] macKey = new byte[32];
        byte[] encKey = new byte[message.getBytes().length];
        byte [] concatenatedKeys = new byte [macKey.length+encKey.length];
        
        //Creation des paramètres
        DerivationParameters kdfParams = new KDFParameters(kaSharedSecretEncryption, null);
        
        //Creation du générateur de clé dérivé avec SHA-256 
        KDF2BytesGenerator kdf2 = new KDF2BytesGenerator(new SHA256Digest());
        
        //Initialisation avec les paramètres
        kdf2.init(kdfParams);
        
        //Génération de l'output
        kdf2.generateBytes(concatenatedKeys, 0, concatenatedKeys.length);
        
        System.arraycopy(concatenatedKeys, 0, encKey, 0, message.getBytes().length);
        System.arraycopy(concatenatedKeys, message.getBytes().length, macKey, 0, 32);
        System.out.println("\nClé MAC : \n"+Hex.toHexString(macKey)+"\n"+macKey.length+" octets");
        System.out.println("\nClé de chiffrement : \n"+Hex.toHexString(encKey)+"\n"+encKey.length+" octets");
        
        //Chiffrement XOR
        byte[] encryptedMessage = ByteUtils.xor(message.getBytes(), encKey);
        System.out.println("\nMessage chiffré : \n"+Hex.toHexString(encryptedMessage)+"\n"+encryptedMessage.length+" octets");
        
        //MAC1 avec SHA-256
        HMac operator = new HMac(new SHA256Digest());      
        operator.init(new KeyParameter(macKey));
        operator.update(encryptedMessage, 0, encryptedMessage.length);
        byte[]  resBuf = new byte[32];
        operator.doFinal(resBuf, 0);
        
        //Troncature des 16 premiers octets 
        byte[]  tag = new byte[16];
        System.arraycopy(resBuf, 0, tag, 0, 16);
        System.out.println("\nTAG : \n"+Hex.toHexString(tag)+"\n"+tag.length+" octets");
            
        System.out.println("\n*******************DECHIFFREMENT**********************\n");
        //Fonction KA
        //Création du secret partagé
        ECDHCBasicAgreement serverKeyAgree = new ECDHCBasicAgreement();
        serverKeyAgree.init(serverKeyPair.getPrivate());
        BigInteger serverSecret = serverKeyAgree.calculateAgreement(clientKeyPair.getPublic());
        byte[] kaSharedSecretDecryption = serverSecret.toByteArray();//here
        System.out.println("Valeur du secret partagé recalculé: \n"+serverSecret.toString(16)+"\n"+serverSecret.toString(16).length()/2+" octets");//here
            
        //KDF2 avec SHA-256
        byte[] recalculatedMacKey = new byte[32];
        byte[] recalculatedEncKey = new byte[message.getBytes().length];
        byte [] recalculatedConcatenatedKeys = new byte [recalculatedMacKey.length+recalculatedEncKey.length];
        
        //Creation des paramètres
        DerivationParameters kdfParamsDecryption = new KDFParameters(kaSharedSecretDecryption, null);
        
        //Creation du générateur de clé dérivé avec SHA-256 
        KDF2BytesGenerator kdf2Decryption = new KDF2BytesGenerator(new SHA256Digest());
        
        //Initialisation du générateur
        kdf2Decryption.init(kdfParamsDecryption);
        
        //Output
        kdf2Decryption.generateBytes(recalculatedConcatenatedKeys, 0, recalculatedConcatenatedKeys.length);
        
        System.arraycopy(recalculatedConcatenatedKeys, 0, recalculatedEncKey, 0, message.getBytes().length);
        System.arraycopy(recalculatedConcatenatedKeys, message.getBytes().length, recalculatedMacKey, 0, 32);
        System.out.println("\nClé MAC recalculée : \n"+Hex.toHexString(recalculatedMacKey)+" "+recalculatedMacKey.length+" octets");
        System.out.println("\nClé de chiffrement recalculée : \n"+Hex.toHexString(recalculatedEncKey)+" "+recalculatedEncKey.length+" octets");
            
        //MAC1 avec SHA-256
        HMac operatorDecryption = new HMac(new SHA256Digest());      
        operatorDecryption.init(new KeyParameter(recalculatedMacKey));
        operatorDecryption.update(encryptedMessage, 0, encryptedMessage.length);
        byte[]  resBufBis = new byte[32];
        operatorDecryption.doFinal(resBufBis, 0);
        
        //Troncature des 16 premiers octets
        byte[] recalculatedTag = new byte[16];
        System.arraycopy(resBufBis, 0, recalculatedTag, 0, 16);
        System.out.println("\nTAG : \n"+Hex.toHexString(recalculatedTag)+" "+recalculatedTag.length+" octets"); 
        
        //comparaison par rapport aux 2 tags
        System.out.println("\nAuthentification bonne ? "+ Arrays.equals(tag, recalculatedTag));
        System.out.println("tag : " + Hex.toHexString(tag) + "\nTag recalculé : " + Hex.toHexString(recalculatedTag)+ "\n");
        
        //Déchiffrement XOR
        byte[] decryptedMessage = ByteUtils.xor(encryptedMessage, recalculatedEncKey);
        System.out.println("\nMessage dechiffré: \n"+new String(decryptedMessage, "UTF-8")+" \nValeur hexadécimale : "+ Hex.toHexString(decryptedMessage) +"\n"+decryptedMessage.length+" octets");
        
    }
}