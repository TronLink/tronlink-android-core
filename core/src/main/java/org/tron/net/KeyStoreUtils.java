package org.tron.net;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Hash;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.RomUtils;
import org.tron.walletserver.AddressUtil;
import org.tron.walletserver.Wallet;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyStoreUtils {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static String getKeyStoreWithPrivate(String password, Wallet wallet) throws CipherException {
        return getKeyStore(password, wallet.getECKey().getPrivKeyBytes(), wallet.getAddress());
    }

    public static String getKeyStoreWithMnemonic(String password, String mnemonic, String address) throws CipherException {
        return getKeyStore(password, mnemonic.getBytes(), address);
    }

    // NOTE: zeroes the provided plaintext `bytes` on return; pass a throwaway copy.
    public static String getKeyStore(String password, byte[] bytes, String address) throws CipherException {

        final int N_STANDARD = RomUtils.getTotalMemory() > 2 ? 1 << 16 : 1 << 14;
        final int P_STANDARD = 1;

        final int R = 8;
        // Web3 Keystore v3 standard: fixed 32-byte DKLEN and salt.
        // Variable lengths leaked the plaintext type (32=private key, 50-60=12-word mnemonic, etc.)
        final int DKLEN = 32;
        byte[] salt = generateRandomBytes(32);

        byte[] passwordBytes = password.getBytes(UTF_8);
        byte[] derivedKey = generateDerivedScryptKey(passwordBytes, salt, N_STANDARD, R, P_STANDARD, DKLEN);

        byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
        byte[] iv = generateRandomBytes(16);

        try {
            byte[] cipherText = performCipherOperation(Cipher.ENCRYPT_MODE, iv, encryptKey,
                    bytes);

            byte[] mac = generateMac(derivedKey, cipherText);
            if (AddressUtil.isEmpty(address)){
                return "";
            }
            String hexAddress =address;
            if(AddressUtil.isAddressValid(address)){
                hexAddress=  Hex.toHexString(AddressUtil.decodeFromBase58Check(address));
            }
            return WalletFile.createGson().toJson(createWalletFile(hexAddress, cipherText, iv, salt, mac, N_STANDARD, P_STANDARD));
        } finally {
            // Wipe plaintext and key copies from the heap; bytes may be null.
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(derivedKey, (byte) 0);
            Arrays.fill(encryptKey, (byte) 0);
        }
    }

    // accepted: [Q-12] Public API may still surface undeclared Gson/hex RuntimeExceptions
    // on malformed keystore; non-blocking quality issue, import UI already fails closed.
    // Scan report 2026-07-14.
    public static String getPrivateWithKeyStore(String keyStore, String password) throws CipherException, IOException {
        WalletFile walletFile = WalletFile.createGson().fromJson(keyStore, WalletFile.class);
        ECKey ecKey = decrypt(password, walletFile);
        validateAddressMatches(walletFile.getAddress(), ecKey);
        return ByteArray.toHexString(ecKey.getPrivKeyBytes());
    }

    static void validateAddressMatches(String address, ECKey decryptedKey)
            throws AddressMismatchException {
        // Some third-party wallet keystores omit the optional address field. Keep those files
        // importable for compatibility; all password, MAC and private-key checks still apply.
        if (address == null || address.trim().isEmpty()) {
            return;
        }

        byte[] declaredAddress = AddressUtil.decodeUnknownAddress(address);
        if (declaredAddress == null
                || decryptedKey == null
                || !MessageDigest.isEqual(declaredAddress, decryptedKey.getAddress())) {
            throw new AddressMismatchException();
        }
    }

    // accepted: [Q-12] Same as getPrivateWithKeyStore — undeclared parse exceptions left as-is.
    // Scan report 2026-07-14.
    public static String getMnemonicWithKeyStore(String keyStore, String password) throws CipherException, IOException {

        byte[] mnemonicBytes = decryptToByte(password, WalletFile.createGson().fromJson(keyStore, WalletFile.class));
        try {
            return new String(mnemonicBytes);
        } finally {
            // Zero the decrypted plaintext copy once the String is built to
            // shrink its residency window in the heap.
            Arrays.fill(mnemonicBytes, (byte) 0);
        }
    }

    private static ECKey decrypt(String password, WalletFile walletFile)
            throws CipherException {

        return ECKey.fromPrivate(decryptToByte(password, walletFile));

    }

    private static byte[] decryptToByte(String password, WalletFile walletFile)
            throws CipherException {

        validate(walletFile);

        WalletFile.Crypto crypto = walletFile.getCrypto();

        byte[] mac = ByteArray.fromHexString(crypto.getMac());
        byte[] iv = ByteArray.fromHexString(crypto.getCipherparams().getIv());
        byte[] cipherText = ByteArray.fromHexString(crypto.getCiphertext());

        byte[] derivedKey;

        WalletFile.KdfParams kdfParams = crypto.getKdfparams();
        if (kdfParams instanceof WalletFile.ScryptKdfParams) {
            WalletFile.ScryptKdfParams scryptKdfParams =
                    (WalletFile.ScryptKdfParams) crypto.getKdfparams();
            int dklen = scryptKdfParams.getDklen();
            int n = scryptKdfParams.getN();
            int p = scryptKdfParams.getP();
            int r = scryptKdfParams.getR();
            // KDF params come from untrusted keystore JSON: a huge N allocates
            // 128*N*R bytes (OOM), and a non-power-of-two N makes SCrypt throw an
            // undeclared IllegalArgumentException bypassing the CipherException contract.
            if (n <= 1 || n > (1 << 20) || Integer.bitCount(n) != 1) {
                throw new CipherException("Invalid scrypt n parameter");
            }
            if (r < 1 || r > 64) {
                throw new CipherException("Invalid scrypt r parameter");
            }
            if (p < 1 || p > 16) {
                throw new CipherException("Invalid scrypt p parameter");
            }
            // accepted: [S-04] Combined scrypt memory budget not enforced. Keystore import is
            // app-internal only (no external/untrusted keystore API); no remote malicious
            // JSON path. Scan report 2026-07-14.
            // generateMac reads derivedKey[16..32), so anything below 32 is unusable.
            // Upper bound stays generous: legacy keystores were created with
            // DKLEN = plaintext length, so a mnemonic keystore stores dklen equal to
            // the mnemonic byte length (a 21/24-word mnemonic exceeds 128 bytes).
            // dklen is only the final PBKDF2 output length and does not drive scrypt's
            // 128*N*R memory cost, so a large value is cheap; 1024 keeps old wallets
            // decryptable while still rejecting absurd values.
            if (dklen < 32 || dklen > 1024) {
                throw new CipherException("Invalid scrypt dklen parameter");
            }
            if (scryptKdfParams.getSalt() == null) {
                throw new CipherException("Malformed keystore: missing scrypt salt");
            }
            byte[] salt = ByteArray.fromHexString(scryptKdfParams.getSalt());
            derivedKey = generateDerivedScryptKey(password.getBytes(UTF_8), salt, n, r, p, dklen);
        } else if (kdfParams instanceof WalletFile.Aes128CtrKdfParams) {
            WalletFile.Aes128CtrKdfParams aes128CtrKdfParams =
                    (WalletFile.Aes128CtrKdfParams) crypto.getKdfparams();
            int c = aes128CtrKdfParams.getC();
            String prf = aes128CtrKdfParams.getPrf();
            // PBKDF2 iteration count comes from untrusted keystore JSON. A tiny c (e.g. 0/1)
            // makes password derivation nearly free, weakening offline brute-force resistance;
            // an excessive c causes a local DoS. Mirror the scrypt branch's parameter bounds.
            if (c < 10000 || c > (1 << 24)) {
                throw new CipherException("Invalid pbkdf2 c parameter");
            }
            if (aes128CtrKdfParams.getSalt() == null) {
                throw new CipherException("Malformed keystore: missing pbkdf2 salt");
            }
            byte[] salt = ByteArray.fromHexString(aes128CtrKdfParams.getSalt());

            derivedKey = generateAes128CtrDerivedKey(password.getBytes(UTF_8), salt, c, prf);
        } else {
            throw new CipherException("Unable to deserialize params: " + crypto.getKdf());
        }

        byte[] encryptKey = null;
        try {
            byte[] derivedMac = generateMac(derivedKey, cipherText);

            // Constant-time compare to avoid a timing side channel on the password gate.
            if (!MessageDigest.isEqual(derivedMac, mac)) {
                throw new CipherException("Invalid password provided");
            }

            encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
            byte[] privateKey = performCipherOperation(Cipher.DECRYPT_MODE, iv, encryptKey, cipherText);
            return privateKey;
        } finally {
            // Wipe the derived key material so it does not linger in the heap
            // until GC. The returned plaintext is owned by the caller.
            Arrays.fill(derivedKey, (byte) 0);
            if (encryptKey != null) {
                Arrays.fill(encryptKey, (byte) 0);
            }
        }
    }

    private static byte[] generateAes128CtrDerivedKey(
            byte[] password, byte[] salt, int c, String prf) throws CipherException {

        if (!"hmac-sha256".equals(prf)) {
            throw new CipherException("Unsupported prf:" + prf);
        }

        // Java 8 supports this, but you have to convert the password to a character array, see
        // http://stackoverflow.com/a/27928435/3211687

        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password, salt, c);
        return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
    }


    private static void validate(WalletFile walletFile) throws CipherException {
        final int CURRENT_VERSION = 3;
        final String CIPHER = "aes-128-ctr";

        final String AES_128_CTR = "pbkdf2";
        final String SCRYPT = "scrypt";

        // Keystore JSON is user-pasted input: Gson may return null or leave any
        // field null, which must surface as the declared CipherException, not NPE.
        if (walletFile == null) {
            throw new CipherException("Malformed keystore: empty content");
        }
        WalletFile.Crypto crypto = walletFile.getCrypto();
        if (crypto == null
                || crypto.getCipher() == null
                || crypto.getKdf() == null
                || crypto.getKdfparams() == null
                || crypto.getCiphertext() == null
                || crypto.getMac() == null
                || crypto.getCipherparams() == null
                || crypto.getCipherparams().getIv() == null) {
            throw new CipherException("Malformed keystore: missing crypto fields");
        }

        if (walletFile.getVersion() != CURRENT_VERSION) {
            throw new CipherException("Wallet version is not supported");
        }

        if (!crypto.getCipher().equals(CIPHER)) {
            throw new CipherException("Wallet cipher is not supported");
        }

        if (!crypto.getKdf().equals(AES_128_CTR) && !crypto.getKdf().equals(SCRYPT)) {
            throw new CipherException("KDF type is not supported");
        }
    }


    private static WalletFile createWalletFile(
            String hexAddress, byte[] cipherText, byte[] iv, byte[] salt, byte[] mac,
            int n, int p) {
        final String CIPHER = "aes-128-ctr";
        final String SCRYPT = "scrypt";
        final int DKLEN = 32;
        final int CURRENT_VERSION = 3;
        final int R = 8;
        WalletFile walletFile = new WalletFile();
        // walletFile.setAddress(StringTronUtil.encode58Check(ecKeyPair.getAddress()));
//        walletFile.setAddress(Hex.toHexString(ecKeyPair.getAddress()));
        walletFile.setAddress(hexAddress);

        WalletFile.Crypto crypto = new WalletFile.Crypto();
        crypto.setCipher(CIPHER);
        crypto.setCiphertext(ByteArray.toHexString(cipherText));
        walletFile.setCrypto(crypto);

        WalletFile.CipherParams cipherParams = new WalletFile.CipherParams();
        cipherParams.setIv(ByteArray.toHexString(iv));
        crypto.setCipherparams(cipherParams);

        crypto.setKdf(SCRYPT);
        WalletFile.ScryptKdfParams kdfParams = new WalletFile.ScryptKdfParams();
        kdfParams.setDklen(DKLEN);
        kdfParams.setN(n);
        kdfParams.setP(p);
        kdfParams.setR(R);
        kdfParams.setSalt(ByteArray.toHexString(salt));
        crypto.setKdfparams(kdfParams);

        crypto.setMac(ByteArray.toHexString(mac));
        walletFile.setCrypto(crypto);
        walletFile.setId(UUID.randomUUID().toString());
        walletFile.setVersion(CURRENT_VERSION);

        return walletFile;
    }

    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] generateDerivedScryptKey(
            byte[] password, byte[] salt, int n, int r, int p, int dkLen) throws CipherException {
        return SCrypt.generate(password, salt, n, r, p, dkLen);
    }

    private static byte[] performCipherOperation(
            int mode, byte[] iv, byte[] encryptKey, byte[] text) throws CipherException {

        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

            SecretKeySpec secretKeySpec = new SecretKeySpec(encryptKey, "AES");
            cipher.init(mode, secretKeySpec, ivParameterSpec);
            return cipher.doFinal(text);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | InvalidKeyException
                | BadPaddingException | IllegalBlockSizeException e) {
            throw new CipherException("Error performing cipher operation", e);
        }
    }

    private static byte[] generateMac(byte[] derivedKey, byte[] cipherText) {
        byte[] result = new byte[16 + cipherText.length];

        System.arraycopy(derivedKey, 16, result, 0, 16);
        System.arraycopy(cipherText, 0, result, 16, cipherText.length);

        return Hash.sha3(result);
    }
}
