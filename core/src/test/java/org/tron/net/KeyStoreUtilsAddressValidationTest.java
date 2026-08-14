package org.tron.net;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;
import org.tron.walletserver.AddressUtil;

import java.math.BigInteger;
import java.util.Locale;

public class KeyStoreUtilsAddressValidationTest {

    private static final ECKey IMPORTED_KEY = ECKey.fromPrivate(BigInteger.ONE);
    private static final ECKey DIFFERENT_KEY = ECKey.fromPrivate(BigInteger.TWO);

    @Test
    public void validateAddressMatches_accepts41HexAddress() throws Exception {
        String address = Hex.toHexString(IMPORTED_KEY.getAddress());

        KeyStoreUtils.validateAddressMatches(address, IMPORTED_KEY);
        KeyStoreUtils.validateAddressMatches(address.toUpperCase(Locale.ROOT), IMPORTED_KEY);
    }

    @Test
    public void validateAddressMatches_acceptsBase58Address() throws Exception {
        String address = AddressUtil.encode58Check(IMPORTED_KEY.getAddress());

        KeyStoreUtils.validateAddressMatches(address, IMPORTED_KEY);
    }

    @Test
    public void validateAddressMatches_skipsEmptyAddressForThirdPartyCompatibility()
            throws Exception {
        KeyStoreUtils.validateAddressMatches(null, IMPORTED_KEY);
        KeyStoreUtils.validateAddressMatches("", IMPORTED_KEY);
        KeyStoreUtils.validateAddressMatches("   ", IMPORTED_KEY);
    }

    @Test
    public void validateAddressMatches_rejectsMismatched41HexAddress() {
        assertAddressMismatch(Hex.toHexString(DIFFERENT_KEY.getAddress()));
    }

    @Test
    public void validateAddressMatches_rejectsMismatchedBase58Address() {
        assertAddressMismatch(AddressUtil.encode58Check(DIFFERENT_KEY.getAddress()));
    }

    @Test
    public void validateAddressMatches_rejectsMalformedNonEmptyAddress() {
        assertAddressMismatch("not-a-tron-address");
        assertAddressMismatch("null");
    }

    private static void assertAddressMismatch(String address) {
        try {
            KeyStoreUtils.validateAddressMatches(address, IMPORTED_KEY);
            Assert.fail("address mismatch must be rejected: " + address);
        } catch (AddressMismatchException expected) {
            Assert.assertTrue(expected.getMessage().contains("address"));
        }
    }
}
