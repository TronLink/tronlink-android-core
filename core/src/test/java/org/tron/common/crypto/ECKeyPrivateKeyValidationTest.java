package org.tron.common.crypto;

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class ECKeyPrivateKeyValidationTest {

    @Test
    public void fromPrivate_rejectsValuesOutsideSecp256k1Range() {
        assertIllegalPrivateKey(BigInteger.ZERO);
        assertIllegalPrivateKey(ECKey.CURVE.getN());
        assertIllegalPrivateKey(ECKey.CURVE.getN().add(BigInteger.ONE));
        assertIllegalPrivateKey(BigInteger.valueOf(-1));
    }

    @Test
    public void fromPrivate_acceptsSecp256k1BoundaryValues() {
        Assert.assertTrue(ECKey.fromPrivate(BigInteger.ONE).hasPrivKey());
        Assert.assertTrue(
                ECKey.fromPrivate(ECKey.CURVE.getN().subtract(BigInteger.ONE)).hasPrivKey());
    }

    @Test
    public void byteArrayPrivateKeyEntryPoint_rejectsZero() {
        try {
            ECKey.fromPrivate(new byte[32]);
            Assert.fail("zero private key must be rejected");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage().contains("range"));
        }
    }

    @Test
    public void privateKeyConstructor_rejectsZero() {
        try {
            new ECKey(new byte[32], true);
            Assert.fail("zero private key must be rejected");
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage().contains("range"));
        }
    }

    private static void assertIllegalPrivateKey(BigInteger value) {
        try {
            ECKey.fromPrivate(value);
            Assert.fail("out-of-range private key must be rejected: " + value);
        } catch (IllegalArgumentException expected) {
            Assert.assertTrue(expected.getMessage().contains("range"));
        }
    }
}
