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

    public static String getKeyStore(String password, byte[] bytes, String address) throws CipherException {

        final int N_STANDARD = RomUtils.getTotalMemory() > 2 ? 1 << 16 : 1 << 14;
        final int P_STANDARD = 1;

        final int R = 8;
        final int DKLEN = bytes.length;
        byte[] salt = generateRandomBytes(bytes.length);

        byte[] derivedKey = generateDerivedScryptKey(password.getBytes(UTF_8), salt, N_STANDARD, R, P_STANDARD, DKLEN);

        byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
        byte[] iv = generateRandomBytes(16);


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
    }

    public static String getPrivateWithKeyStore(String keyStore, String password) throws CipherException, IOException {

        return ByteArray.toHexString(decrypt(password, WalletFile.createGson().fromJson(keyStore, WalletFile.class)).getPrivKeyBytes());
    }

    public static String getMnemonicWithKeyStore(String keyStore, String password) throws CipherException, IOException {

        return new String(decryptToByte(password, WalletFile.createGson().fromJson(keyStore, WalletFile.class)));
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
            byte[] salt = ByteArray.fromHexString(scryptKdfParams.getSalt());
            derivedKey = generateDerivedScryptKey(password.getBytes(UTF_8), salt, n, r, p, dklen);
        } else if (kdfParams instanceof WalletFile.Aes128CtrKdfParams) {
            WalletFile.Aes128CtrKdfParams aes128CtrKdfParams =
                    (WalletFile.Aes128CtrKdfParams) crypto.getKdfparams();
            int c = aes128CtrKdfParams.getC();
            String prf = aes128CtrKdfParams.getPrf();
            byte[] salt = ByteArray.fromHexString(aes128CtrKdfParams.getSalt());

            derivedKey = generateAes128CtrDerivedKey(password.getBytes(UTF_8), salt, c, prf);
        } else {
            throw new CipherException("Unable to deserialize params: " + crypto.getKdf());
        }

        byte[] derivedMac = generateMac(derivedKey, cipherText);

        if (!Arrays.equals(derivedMac, mac)) {
            throw new CipherException("Invalid password provided");
        }

        byte[] encryptKey = Arrays.copyOfRange(derivedKey, 0, 16);
        byte[] privateKey = performCipherOperation(Cipher.DECRYPT_MODE, iv, encryptKey, cipherText);
        return privateKey;

    }

    private static byte[] generateAes128CtrDerivedKey(
            byte[] password, byte[] salt, int c, String prf) throws CipherException {

        if (!prf.equals("hmac-sha256")) {
            throw new CipherException("Unsupported prf:" + prf);
        }

        // Java 8 supports this, but you have to convert the password to a character array, see
        // http://stackoverflow.com/a/27928435/3211687

        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password, salt, c);
        return ((KeyParameter) gen.generateDerivedParameters(256)).getKey();
    }


    private static void validate(WalletFile walletFile) throws CipherException {
        WalletFile.Crypto crypto = walletFile.getCrypto();
        final int CURRENT_VERSION = 3;
        final String CIPHER = "aes-128-ctr";

        final String AES_128_CTR = "pbkdf2";
        final String SCRYPT = "scrypt";

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
        final int DKLEN = salt.length;
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
