package org.tron.walletserver;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

/**
 * Regression tests for replace41Address prefix handling. The result is ABI/EIP-712 encoded
 * as a 20-byte address, so any wrong strip silently changes the signed address.
 */
public class AddressUtilReplace41Test {

    // 20-byte body that itself starts with "41" and ends with "41".
    private static final String BODY_20 = "415cb7e83668d78451a236c86de505d5ff502441";
    private static final String TRON_HEX = "41" + BODY_20;

    @Test
    public void base58Address_stripsOnlyNetworkPrefix() {
        String base58 = AddressUtil.encode58Check(Hex.decode(TRON_HEX));
        Assert.assertTrue(base58.startsWith("T"));
        Assert.assertEquals(BODY_20, AddressUtil.replace41Address(base58));
    }

    @Test
    public void base58Address_withNonTronPrefix_isRejected() {
        // Checksum-valid and starts with "T", but the version byte is 0x42. The old code
        // removed the first "41" found anywhere, here the trailing one, and returned a
        // well-formed but unrelated 40-char address.
        String base58 = AddressUtil.encode58Check(Hex.decode("42" + BODY_20));
        Assert.assertTrue(base58.startsWith("T"));
        assertRejected(base58);
    }

    @Test
    public void base58Address_withWrongLength_isRejected() {
        // 23-byte checksum-valid payload whose Base58 form still starts with "T".
        StringBuilder payload = new StringBuilder("c1");
        for (int i = 0; i < 22; i++) {
            payload.append("41");
        }
        String base58 = AddressUtil.encode58Check(Hex.decode(payload.toString()));
        Assert.assertTrue(base58.startsWith("T"));
        assertRejected(base58);
    }

    @Test
    public void base58Address_withBadChecksum_isRejected() {
        String base58 = AddressUtil.encode58Check(Hex.decode(TRON_HEX));
        char last = base58.charAt(base58.length() - 1);
        String tampered = base58.substring(0, base58.length() - 1) + (last == '1' ? '2' : '1');
        assertRejected(tampered);
    }

    @Test
    public void tronHexAddress_stripsOnlyLeadingPrefix() {
        Assert.assertEquals(BODY_20, AddressUtil.replace41Address(TRON_HEX));
        Assert.assertEquals(BODY_20.toUpperCase(),
                AddressUtil.replace41Address(TRON_HEX.toUpperCase()));
    }

    @Test
    public void prefixedTronHexAddress_stripsBothPrefixes() {
        Assert.assertEquals(BODY_20, AddressUtil.replace41Address("0x" + TRON_HEX));
    }

    @Test
    public void raw20ByteAddressStartingWith41_isPreserved() {
        Assert.assertEquals(BODY_20, AddressUtil.replace41Address(BODY_20));
        Assert.assertEquals(BODY_20, AddressUtil.replace41Address("0x" + BODY_20));
    }

    @Test
    public void raw20ByteAddress_isPreserved() {
        String raw = "5cb7e83668d78451a236c86de505d5ff5024bd99";
        Assert.assertEquals(raw, AddressUtil.replace41Address(raw));
        Assert.assertEquals(raw, AddressUtil.replace41Address("0x" + raw));
    }

    @Test(expected = IllegalArgumentException.class)
    public void nullAddress_isRejected() {
        AddressUtil.replace41Address(null);
    }

    @Test
    public void isTronHexAddress_matchesReplace41Rule() {
        Assert.assertTrue(AddressUtil.isTronHexAddress(TRON_HEX));
        Assert.assertTrue(AddressUtil.isTronHexAddress("0x" + TRON_HEX));
        Assert.assertTrue(AddressUtil.isTronHexAddress(TRON_HEX.toUpperCase()));

        Assert.assertFalse(AddressUtil.isTronHexAddress(null));
        Assert.assertFalse(AddressUtil.isTronHexAddress(""));
        Assert.assertFalse(AddressUtil.isTronHexAddress(BODY_20));
        Assert.assertFalse(AddressUtil.isTronHexAddress("0x" + BODY_20));
        Assert.assertFalse(AddressUtil.isTronHexAddress(TRON_HEX + "00"));
        Assert.assertFalse(AddressUtil.isTronHexAddress("42" + BODY_20));
        Assert.assertFalse(AddressUtil.isTronHexAddress("41" + BODY_20.substring(2) + "zz"));
        Assert.assertFalse(AddressUtil.isTronHexAddress(
                AddressUtil.encode58Check(Hex.decode(TRON_HEX))));
    }

    private static void assertRejected(String address) {
        try {
            String result = AddressUtil.replace41Address(address);
            Assert.fail("Expected IllegalArgumentException, got " + result);
        } catch (IllegalArgumentException expected) {
            // Signing must be aborted instead of using a derived address.
        }
    }
}
