package org.tron.common.crypto;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.bip32.Numeric;

/**
 * Regression tests for Q-11: BIP-39 seed derivation documented UTF-8 NFKD but
 * fed raw UTF-8 to PBKDF2, so canonically equivalent mnemonics/passphrases
 * with different code point sequences derived different seeds.
 */
public class MnemonicUtilsTest {

    /** First official BIP-39 English test vector (passphrase "TREZOR"). */
    private static final String VECTOR_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon abandon abandon about";
    private static final String VECTOR_SEED =
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
                    + "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    @Test
    public void generateSeed_officialVector_matches() {
        byte[] seed = MnemonicUtils.generateSeed(VECTOR_MNEMONIC, "TREZOR");
        Assert.assertEquals(VECTOR_SEED, Numeric.toHexStringNoPrefix(seed));
    }

    @Test
    public void generateSeed_nfcAndNfdPassphrase_deriveSameSeed() {
        String nfc = "café"; // é as a single precomposed code point
        String nfd = "café"; // e + combining acute accent
        byte[] seedNfc = MnemonicUtils.generateSeed(VECTOR_MNEMONIC, nfc);
        byte[] seedNfd = MnemonicUtils.generateSeed(VECTOR_MNEMONIC, nfd);
        Assert.assertArrayEquals(seedNfc, seedNfd);
    }

    @Test
    public void generateSeed_nfcAndNfdMnemonic_deriveSameSeed() {
        // generateSeed does not require wordlist membership, matching BIP-39's
        // treatment of the sentence as an opaque NFKD UTF-8 string.
        byte[] seedNfc = MnemonicUtils.generateSeed("café mnemonic", "");
        byte[] seedNfd = MnemonicUtils.generateSeed("café mnemonic", "");
        Assert.assertArrayEquals(seedNfc, seedNfd);
    }

    @Test
    public void generateSeed_compatibilityCharacters_normalizedByNfkd() {
        // NFKD maps the ligature U+FB01 to the ASCII sequence "fi".
        byte[] ligature = MnemonicUtils.generateSeed(VECTOR_MNEMONIC, "ﬁsh");
        byte[] ascii = MnemonicUtils.generateSeed(VECTOR_MNEMONIC, "fish");
        Assert.assertArrayEquals(ligature, ascii);
    }

    @Test
    public void generateSeed_nullPassphrase_sameAsEmpty() {
        Assert.assertArrayEquals(
                MnemonicUtils.generateSeed(VECTOR_MNEMONIC, ""),
                MnemonicUtils.generateSeed(VECTOR_MNEMONIC, null));
    }

    @Test
    public void generateMnemonic_allZeroEntropy_matchesOfficialVector() {
        Assert.assertEquals(VECTOR_MNEMONIC, MnemonicUtils.generateMnemonic(new byte[16]));
    }

    @Test
    public void generateMnemonic_repeatedByteEntropy_roundTrips() {
        byte[] entropy = new byte[16];
        java.util.Arrays.fill(entropy, (byte) 0x5a);

        String mnemonic = MnemonicUtils.generateMnemonic(entropy);

        Assert.assertArrayEquals(entropy, MnemonicUtils.generateEntropy(mnemonic));
    }

    @Test
    public void generateEntropy_allZeroVector_remainsImportCompatible() {
        Assert.assertArrayEquals(new byte[16], MnemonicUtils.generateEntropy(VECTOR_MNEMONIC));
    }

    @Test
    public void validateMnemonicStrict_rejectsNonCanonicalWhitespace() {
        Assert.assertTrue(MnemonicUtils.validateMnemonicStrict(VECTOR_MNEMONIC));
        Assert.assertFalse(MnemonicUtils.validateMnemonicStrict(VECTOR_MNEMONIC + " "));
        Assert.assertFalse(MnemonicUtils.validateMnemonicStrict(
                VECTOR_MNEMONIC.replace("abandon about", "abandon  about")));
    }
}
