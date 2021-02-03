package com.misterpki;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link Crypto}
 *
 * @author Mister PKI
 */
public class CryptoTest {

  @Test
  public void encryptRSA() throws Exception {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    final String plaintext = "Plain Text";
    final byte[] ciphertext = Crypto.encryptRSA(plaintext, keyPair.getPublic());

    assertThat(Crypto.decryptRSA(ciphertext, keyPair.getPrivate())).isEqualTo(plaintext);
  }

  @Test
  public void encryptAESCBC() throws Exception {
    final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    final SecretKey secretKey = keyGenerator.generateKey();

    final String plaintext = "Plain Text";
    final byte[] ciphertext = Crypto.encryptAESCBC(plaintext, secretKey);

    assertThat(Crypto.decryptAESCBC(ciphertext, secretKey)).isEqualTo(plaintext);
  }

  @Test
  public void encryptAESGCM() throws Exception {
    final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(256);
    final SecretKey secretKey = keyGenerator.generateKey();

    final String plaintext = "Plain Text";
    final byte[] ciphertext = Crypto.encryptAESGCM(plaintext, secretKey);

    assertThat(Crypto.decryptAESGCM(ciphertext, secretKey)).isEqualTo(plaintext);
  }
}
