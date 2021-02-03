package com.misterpki;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Final class containing crypto functions.
 *
 * @author Mister PKI
 */
public final class Crypto {

  /**
   * RSA encrypt data.
   *
   * @param plaintext plain text to be encrypted
   * @param publicKey public key to perform encryption with
   *
   * @return encrypted bytes
   *
   * @throws NoSuchPaddingException if the padding is not a valid padding type
   * @throws NoSuchAlgorithmException if the algorithm is not a valid encryption algorithm
   * @throws InvalidKeyException if the given key is invalid
   * @throws BadPaddingException if the padding mechanism is not expected when performing the encryption
   * @throws IllegalBlockSizeException if the length of the block size does not match the cipher
   */
  public static byte[] encryptRSA(final String plaintext, final PublicKey publicKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
        IllegalBlockSizeException
  {
    final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);

    cipher.update(plaintext.getBytes());
    return cipher.doFinal();
  }

  /**
   * RSA encrypt data.
   *
   * @param ciphertext cipher text to be decrypted
   * @param privateKey private key to perform decryption with
   *
   * @return decrypted String
   *
   * @throws NoSuchPaddingException if the padding is not a valid padding type
   * @throws NoSuchAlgorithmException if the algorithm is not a valid encryption algorithm
   * @throws InvalidKeyException if the given key is invalid
   * @throws BadPaddingException if the padding mechanism is not expected when performing the encryption
   * @throws IllegalBlockSizeException if the length of the block size does not match the cipher
   */
  public static String decryptRSA(final byte[] ciphertext, final PrivateKey privateKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
        IllegalBlockSizeException
  {
    final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return new String(cipher.doFinal(ciphertext));
  }

  /**
   * AES CBC encrypt data.
   *
   * @param plaintext plain text to be encrypted
   * @param secretKey secret key to perform encryption with
   *
   * @return encrypted bytes
   *
   * @throws NoSuchPaddingException if the padding is not a valid padding type
   * @throws NoSuchAlgorithmException if the algorithm is not a valid encryption algorithm
   * @throws InvalidKeyException if the given key is invalid
   * @throws BadPaddingException if the padding mechanism is not expected when performing the encryption
   * @throws IllegalBlockSizeException if the length of the block size does not match the cipher
   */
  public static byte[] encryptAESCBC(final String plaintext, final SecretKey secretKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
        IllegalBlockSizeException, InvalidAlgorithmParameterException
  {
    final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));

    cipher.update(plaintext.getBytes());
    return cipher.doFinal();
  }

  /**
   * AES CBC decrypt data.
   *
   * @param ciphertext cipher text to be decrypted
   * @param secretKey public key to perform decryption with
   *
   * @return decrypted String
   *
   * @throws NoSuchPaddingException if the padding is not a valid padding type
   * @throws NoSuchAlgorithmException if the algorithm is not a valid encryption algorithm
   * @throws InvalidKeyException if the given key is invalid
   * @throws BadPaddingException if the padding mechanism is not expected when performing the encryption
   * @throws IllegalBlockSizeException if the length of the block size does not match the cipher
   */
  public static String decryptAESCBC(final byte[] ciphertext, final SecretKey secretKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
        IllegalBlockSizeException, InvalidAlgorithmParameterException
  {
    final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
    return new String(cipher.doFinal(ciphertext));
  }

  /**
   * AES GCM encrypt data.
   *
   * @param plaintext plain text to be encrypted
   * @param secretKey secret key to perform encryption with
   *
   * @return encrypted bytes
   *
   * @throws NoSuchPaddingException if the padding is not a valid padding type
   * @throws NoSuchAlgorithmException if the algorithm is not a valid encryption algorithm
   * @throws InvalidKeyException if the given key is invalid
   * @throws BadPaddingException if the padding mechanism is not expected when performing the encryption
   * @throws IllegalBlockSizeException if the length of the block size does not match the cipher
   */
  public static byte[] encryptAESGCM(final String plaintext, final SecretKey secretKey) throws NoSuchPaddingException,
      NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
        IllegalBlockSizeException
  {
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    final SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
    final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, new byte[16]);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
    return cipher.doFinal(plaintext.getBytes());
  }

  /**
   * AES GCM decrypt data.
   *
   * @param ciphertext cipher text to be decrypted
   * @param secretKey secret key to perform decryption with
   *
   * @return decrypted String
   *
   * @throws NoSuchPaddingException if the padding is not a valid padding type
   * @throws NoSuchAlgorithmException if the algorithm is not a valid encryption algorithm
   * @throws InvalidKeyException if the given key is invalid
   * @throws BadPaddingException if the padding mechanism is not expected when performing the encryption
   * @throws IllegalBlockSizeException if the length of the block size does not match the cipher
   */
  public static String decryptAESGCM(final byte[] ciphertext, final SecretKey secretKey) throws NoSuchPaddingException,
      NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException,
        IllegalBlockSizeException
  {
    final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    final SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
    final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, new byte[16]);
    cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
    return new String(cipher.doFinal(ciphertext));
  }
}
