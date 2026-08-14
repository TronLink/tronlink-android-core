package org.tron.walletserver;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.ECKey;

import java.math.BigInteger;

public class WalletPrivateKeyValidationTest {

    @Test
    public void privateKeyImport_acceptsSecp256k1Boundaries() {
        Assert.assertTrue(importPrivateKey(BigInteger.ONE).isOpen());
        Assert.assertTrue(importPrivateKey(ECKey.CURVE.getN().subtract(BigInteger.ONE)).isOpen());
    }

    @Test
    public void privateKeyImport_rejectsValuesOutsideSecp256k1Range() {
        Assert.assertFalse(importPrivateKey(BigInteger.ZERO).isOpen());
        Assert.assertFalse(importPrivateKey(ECKey.CURVE.getN()).isOpen());
        Assert.assertFalse(importPrivateKey(ECKey.CURVE.getN().add(BigInteger.ONE)).isOpen());
    }

    @Test
    public void privateKeyImport_doesNotTreatOneAndNPlusOneAsAliases() {
        Wallet validWallet = importPrivateKey(BigInteger.ONE);
        Wallet outOfRangeWallet = importPrivateKey(ECKey.CURVE.getN().add(BigInteger.ONE));

        Assert.assertTrue(validWallet.isOpen());
        Assert.assertFalse(outOfRangeWallet.isOpen());
    }

    private static Wallet importPrivateKey(BigInteger privateKey) {
        return new Wallet(I_TYPE.PRIVATE, String.format("%064x", privateKey));
    }
}
