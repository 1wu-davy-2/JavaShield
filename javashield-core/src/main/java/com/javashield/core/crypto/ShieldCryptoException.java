package com.javashield.core.crypto;

/**
 * Raised when an envelope cannot be authenticated or decrypted.
 *
 * <p>The message is deliberately uniform for all authentication failures so that
 * callers cannot use the error text to distinguish a wrong key from a corrupted
 * payload.
 */
public class ShieldCryptoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ShieldCryptoException(String message) {
        super(message);
    }

    public ShieldCryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
