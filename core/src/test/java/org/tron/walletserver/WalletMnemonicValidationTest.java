package org.tron.walletserver;

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

public class WalletMnemonicValidationTest {

    private static final String VALID_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon abandon abandon about";
    private static final String UNKNOWN_WORD_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon abandon abandon tronlink";
    private static final String INVALID_CHECKSUM_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon "
                    + "abandon abandon abandon abandon abandon abandon";

    @Test
    public void mnemonicImport_preservesLegacyNonEmptyPhraseCompatibility() {
        Wallet unknownWordWallet = new Wallet(I_TYPE.MNEMONIC, UNKNOWN_WORD_MNEMONIC);
        Wallet invalidChecksumWallet = new Wallet(I_TYPE.MNEMONIC, INVALID_CHECKSUM_MNEMONIC);

        Assert.assertTrue(unknownWordWallet.isOpen());
        Assert.assertTrue(invalidChecksumWallet.isOpen());
    }

    @Test
    public void strictMnemonicImport_acceptsValidBip39Mnemonic() {
        Wallet wallet = new Wallet(I_TYPE.MNEMONIC_STRICT_VERIFICATION, VALID_MNEMONIC);

        Assert.assertTrue(wallet.isOpen());
    }

    @Test
    public void strictMnemonicImport_rejectsWordOutsideEnglishWordList() {
        Wallet wallet = new Wallet(I_TYPE.MNEMONIC_STRICT_VERIFICATION,
                UNKNOWN_WORD_MNEMONIC);

        Assert.assertFalse(wallet.isOpen());
    }

    @Test
    public void strictMnemonicImport_rejectsInvalidBip39Checksum() {
        Wallet wallet = new Wallet(I_TYPE.MNEMONIC_STRICT_VERIFICATION,
                INVALID_CHECKSUM_MNEMONIC);

        Assert.assertFalse(wallet.isOpen());
    }

    @Test
    public void strictMnemonicImport_rejectsNonCanonicalWhitespace() {
        String[] nonCanonicalMnemonics = {
                " " + VALID_MNEMONIC,
                VALID_MNEMONIC + " ",
                VALID_MNEMONIC.replace("abandon about", "abandon  about"),
                VALID_MNEMONIC.replace("abandon about", "abandon\tabout"),
                VALID_MNEMONIC.replace("abandon about", "abandon\nabout"),
                VALID_MNEMONIC.replace("abandon about", "abandon\u00a0about")
        };

        for (String mnemonic : nonCanonicalMnemonics) {
            Wallet wallet = new Wallet(I_TYPE.MNEMONIC_STRICT_VERIFICATION, mnemonic);
            Assert.assertFalse(wallet.isOpen());
        }
    }

    @Test
    public void mnemonicImport_preservesLegacyWhitespaceDerivation() {
        String legacyMnemonic = VALID_MNEMONIC + " ";
        Wallet canonicalWallet = new Wallet(I_TYPE.MNEMONIC, VALID_MNEMONIC);
        Wallet legacyWallet = new Wallet(I_TYPE.MNEMONIC, legacyMnemonic);

        Assert.assertTrue(canonicalWallet.isOpen());
        Assert.assertTrue(legacyWallet.isOpen());
        Assert.assertFalse(Arrays.equals(
                canonicalWallet.getPrivateKey(), legacyWallet.getPrivateKey()));
    }

    @Test
    public void customPathMnemonicImport_preservesLegacyCompatibility() {
        String legacyMnemonic = VALID_MNEMONIC + " ";
        Wallet wallet = new Wallet(legacyMnemonic, WalletPath.createDefault());

        Assert.assertTrue(wallet.isOpen());
        Assert.assertEquals(legacyMnemonic, wallet.getMnemonic());
    }
}
