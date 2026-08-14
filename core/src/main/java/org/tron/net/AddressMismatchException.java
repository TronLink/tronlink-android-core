package org.tron.net;

/**
 * Thrown when the address declared by a keystore does not match the address derived from its
 * decrypted private key.
 */
public class AddressMismatchException extends CipherException {

    public AddressMismatchException() {
        super("Keystore address does not match the decrypted private key");
    }
}
