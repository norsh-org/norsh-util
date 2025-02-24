package org.norsh.security;

import org.norsh.util.DataConverter;
import org.norsh.util.StringUtil;

/**
 * Service for handling cryptographic signature operations, such as verifying signatures
 * and signing data for validation purposes.
 *
 * <p>
 * This service is designed to facilitate secure operations on data, ensuring authenticity
 * and integrity through cryptographic signatures.
 * </p>
 *
 * <h2>Features:</h2>
 * <ul>
 * <li>Verification of signatures using public keys.</li>
 * <li>Creation of cryptographic signatures using private keys.</li>
 * <li>Concatenation and hashing of multiple fields for consistent signature validation.</li>
 * </ul>
 *
 * @license NCL-R
 * @author Danthur Lice
 * @since 01/2025
 * @version 1.0
 * @see <a href="https://docs.norsh.org">Norsh Documentation</a>
 */
public class Signature {
    public static boolean verifySignature(String publicKey, String signature, Object... values) {
    	return verifySignatureHash(publicKey, signature, Hasher.sha256Hex(StringUtil.concatenate(values)));
    }
  
    /**
     * Verifies the signature for a given public key and a message represented as concatenated fields.
     *
     * @param publicKey the public key in Base64 or Hexadecimal format.
     * @param signature the signature in Base64 or Hexadecimal format.
     * @param values    the fields to be concatenated and hashed for verification.
     * @return {@code true} if the signature is valid, {@code false} otherwise.
     */
    public static boolean verifySignatureHash(String publicKey, String signature, String hash) {
        if (publicKey == null || signature == null) {
            throw new IllegalArgumentException("Public key and signature must not be null.");
        }

        try {
            // Hash the provided data
            byte[] messageBytes = DataConverter.hexToBytes(hash);

            // Convert public key and signature to bytes
            byte[] publicKeyBytes = DataConverter.base64OrHexToBytes(publicKey);
            byte[] signatureBytes = DataConverter.base64OrHexToBytes(signature);

            // Verify the signature
            Cryptography cryptography = Cryptography.valueOf(null, publicKeyBytes);
            boolean isValid = cryptography.verifySignature(messageBytes, signatureBytes);

            return isValid;

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Signs the concatenated fields using the provided private key.
     *
     * @param privateKey the private key in Base64 format.
     * @param values     the fields to be concatenated and signed.
     * @return the signature as a hexadecimal string.
     */
    public static String sign(String privateKey, Object... values) {
        return signHash(privateKey, Hasher.sha256Hex(StringUtil.concatenate(values)));
    }
    
    /**
     * Signs the concatenated fields using the provided private key.
     *
     * @param privateKey the private key in Base64 format.
     * @param hash    
     * @return the signature as a hexadecimal string.
     */
    public static String signHash(String privateKey, String hash) {
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key must not be null.");
        }

        try {
            Cryptography cryptography = Cryptography.valueOf(DataConverter.base64OrHexToBytes(privateKey), null);
            byte[] signatureBytes = cryptography.signData(hash.getBytes());
            String signature = DataConverter.bytesToHex(signatureBytes);

            return signature;

        } catch (Exception e) {
            throw new RuntimeException("Failed to sign data.", e);
        }
    }
}
