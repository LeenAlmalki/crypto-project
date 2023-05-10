package crypto;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class rsa {
	
	 public static void main(String[] args) throws NoSuchAlgorithmException,
     NoSuchPaddingException, InvalidKeyException, 
     IllegalBlockSizeException, BadPaddingException {
     KeyPairGenerator keyPairGenerator =
         KeyPairGenerator.getInstance("RSA");
 SecureRandom secureRandom = new SecureRandom();

 keyPairGenerator.initialize(2048,secureRandom);

 KeyPair pair = keyPairGenerator.generateKeyPair();

 PublicKey publicKey = pair.getPublic();

 String publicKeyString =
 Base64.getEncoder().encodeToString(publicKey.getEncoded());

 System.out.println("public key = "+ publicKeyString);

 PrivateKey privateKey = pair.getPrivate();

 String privateKeyString =
 Base64.getEncoder().encodeToString(privateKey.getEncoded());

 System.out.println("private key = "+ privateKeyString);

 //Encrypt Hello world message
 Cipher encryptionCipher = Cipher.getInstance("RSA");
 encryptionCipher.init(Cipher.ENCRYPT_MODE,privateKey);
 String message = "Hello world";
 byte[] encryptedMessage =
 encryptionCipher.doFinal(message.getBytes());
 String encryption =
 Base64.getEncoder().encodeToString(encryptedMessage);
 System.out.println("encrypted message = "+encryption);

 //Decrypt Hello world message
 Cipher decryptionCipher = Cipher.getInstance("RSA");
 decryptionCipher.init(Cipher.DECRYPT_MODE,publicKey);
 byte[] decryptedMessage =
 decryptionCipher.doFinal(encryptedMessage);
 String decryption = new String(decryptedMessage);
 System.out.println("decrypted message = "+decryption);

 System.out.println("hello");

}
	

}



