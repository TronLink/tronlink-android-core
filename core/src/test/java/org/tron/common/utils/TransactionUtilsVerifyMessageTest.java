package org.tron.common.utils;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.walletserver.AddressUtil;

import java.nio.charset.StandardCharsets;

/**
 * Regression guard for S-03: verifyMessage must never validate a too-short
 * signature as true and must never let an exception escape. Behavior is the
 * same before and after the fix (the catch block already returns false); this
 * locks the contract so a future refactor that removes the catch stays safe.
 */
public class TransactionUtilsVerifyMessageTest {

    private static final String ANY_ADDRESS = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

    @Test
    public void shortHexSignature_returnsFalse() {
        // "0x1234" decodes to 2 bytes (< 65); must return false, not throw.
        boolean result = TransactionUtils.verifyMessage("deadbeef", "0x1234", ANY_ADDRESS);
        Assert.assertFalse(result);
    }

    @Test
    public void emptySignature_returnsFalse() {
        boolean result = TransactionUtils.verifyMessage("deadbeef", "", ANY_ADDRESS);
        Assert.assertFalse(result);
    }

    @Test
    public void embeddedHexMarker_cannotReuseSignatureForDifferentMessage() {
        ECKey key = new ECKey();
        String signature = TransactionUtils.signMessageV2(
                "pay100".getBytes(StandardCharsets.UTF_8), key);
        String address = AddressUtil.encode58Check(key.getAddress());

        Assert.assertTrue(TransactionUtils.verifyMessage("pay100", signature, address));
        Assert.assertFalse(TransactionUtils.verifyMessage("pay0x100", signature, address));
    }

    @Test
    public void leadingHexMarker_remainsACompatiblePrefix() {
        ECKey key = new ECKey();
        String signature = TransactionUtils.signMessageV2(
                "pay100".getBytes(StandardCharsets.UTF_8), key);
        String address = AddressUtil.encode58Check(key.getAddress());

        Assert.assertTrue(TransactionUtils.verifyMessage("0xpay100", signature, address));
    }

    @Test
    public void sign_preservesEmbeddedHexMarker() {
        ECKey key = new ECKey();

        Assert.assertNotEquals(
                TransactionUtils.sign("pay100", key),
                TransactionUtils.sign("pay0x100", key));
        Assert.assertEquals(
                TransactionUtils.sign("pay100", key),
                TransactionUtils.sign("0xpay100", key));
    }
}
