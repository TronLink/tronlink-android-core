package org.tron.walletserver;

import org.junit.Assert;
import org.junit.Test;

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
    public void customPathMnemonicImport_preservesLegacyCompatibility() {
        Wallet wallet = new Wallet(UNKNOWN_WORD_MNEMONIC, WalletPath.createDefault());

        Assert.assertTrue(wallet.isOpen());
        Assert.assertEquals(UNKNOWN_WORD_MNEMONIC, wallet.getMnemonic());
    }
}
