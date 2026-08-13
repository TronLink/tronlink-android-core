package org.tron.walletserver;

import org.junit.Assert;
import org.junit.Test;

public class WalletPathTest {

    @Test
    public void buildPathReturnsParsedWalletPath() {
        String pathString = "{\"purpose\":44,\"coinType\":195,\"account\":1,"
                + "\"change\":0,\"accountIndex\":2}";

        Assert.assertEquals("44'/195'/1'/0/2", WalletPath.buildPath(pathString));
    }

    @Test
    public void buildPathThrowsWhenPathStringIsInvalidJson() {
        assertPathParseFailure("not-json");
    }

    @Test
    public void buildWalletPathReturnsParsedWalletPath() {
        String pathString = "{\"purpose\":44,\"coinType\":195,\"account\":1,"
                + "\"change\":0,\"accountIndex\":2}";
        WalletPath walletPath = WalletPath.buildWalletPath(pathString);

        Assert.assertEquals(1, walletPath.account);
        Assert.assertEquals(2, walletPath.accountIndex);
    }

    @Test
    public void buildWalletPathThrowsWhenPathStringIsInvalidJson() {
        try {
            WalletPath.buildWalletPath("not-json");
            Assert.fail("Expected wallet path parsing to fail");
        } catch (IllegalArgumentException expected) {
            Assert.assertEquals("Failed to parse wallet path", expected.getMessage());
        }
    }

    @Test
    public void buildWalletPathRejectsNegativeIndexesAndUnsupportedChange() {
        assertPathValidationFailure("{\"purpose\":44,\"coinType\":195,\"account\":-1,"
                + "\"change\":0,\"accountIndex\":0}");
        assertPathValidationFailure("{\"purpose\":44,\"coinType\":195,\"account\":0,"
                + "\"change\":2,\"accountIndex\":0}");
        assertPathValidationFailure("{\"purpose\":44,\"coinType\":195,\"account\":0,"
                + "\"change\":0,\"accountIndex\":-1}");
    }

    private static void assertPathValidationFailure(String pathString) {
        try {
            WalletPath.buildWalletPath(pathString);
            Assert.fail("Expected wallet path validation to fail");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage().startsWith("Wallet path"));
        }
    }

    private static void assertPathParseFailure(String pathString) {
        try {
            WalletPath.buildPath(pathString);
            Assert.fail("Expected wallet path parsing to fail");
        } catch (IllegalArgumentException expected) {
            Assert.assertEquals("Failed to parse wallet path", expected.getMessage());
        }
    }
}
