package org.tron.walletserver;

import org.junit.Assert;
import org.junit.Test;
import org.tron.common.crypto.MnemonicUtils;

import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

public class WalletEntropyValidationTest {

    @Test
    public void walletCreation_rejectsDegenerateEntropyAndClearsBuffer() {
        RecordingSecureRandom random = new RecordingSecureRandom((byte) 0x5a);

        try {
            new Wallet(true, random);
            Assert.fail("Expected wallet creation to fail");
        } catch (IllegalStateException expected) {
            Assert.assertTrue(
                    expected.getCause() instanceof MnemonicUtils.EntropyQualityException);
        }

        Assert.assertEquals(2, random.invocationCount);
        Assert.assertNotNull(random.output);
        Assert.assertArrayEquals(new byte[16], random.output);
    }

    @Test
    public void walletCreation_retriesDegenerateEntropyOnceAndCanRecover() {
        RecoveringSecureRandom random = new RecoveringSecureRandom();

        Wallet wallet = new Wallet(true, random);

        Assert.assertTrue(wallet.isOpen());
        Assert.assertEquals(2, random.invocationCount);
        Assert.assertNotNull(random.output);
        Assert.assertArrayEquals(new byte[16], random.output);
    }

    @Test
    public void walletCreation_propagatesEntropySourceFailureAsClosedFailure() {
        try {
            new Wallet(true, new FailingSecureRandom());
            Assert.fail("Expected wallet creation to fail");
        } catch (IllegalStateException expected) {
            Assert.assertTrue(expected.getCause() instanceof ProviderException);
        }
    }

    @Test
    public void walletCreation_acceptsNonDegenerateEntropyAndClearsBuffer() {
        RecordingSecureRandom random = new RecordingSecureRandom();

        Wallet wallet = new Wallet(true, random);

        Assert.assertTrue(wallet.isOpen());
        Assert.assertEquals(1, random.invocationCount);
        Assert.assertNotNull(random.output);
        Assert.assertArrayEquals(new byte[16], random.output);
    }

    private static final class RecordingSecureRandom extends SecureRandom {
        private final Byte repeatedValue;
        private byte[] output;
        private int invocationCount;

        private RecordingSecureRandom() {
            repeatedValue = null;
        }

        private RecordingSecureRandom(byte repeatedValue) {
            this.repeatedValue = repeatedValue;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            invocationCount++;
            output = bytes;
            if (repeatedValue != null) {
                Arrays.fill(bytes, repeatedValue);
                return;
            }
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) i;
            }
        }
    }

    private static final class RecoveringSecureRandom extends SecureRandom {
        private byte[] output;
        private int invocationCount;

        @Override
        public void nextBytes(byte[] bytes) {
            invocationCount++;
            output = bytes;
            if (invocationCount == 1) {
                Arrays.fill(bytes, (byte) 0);
                return;
            }
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) i;
            }
        }
    }

    private static final class FailingSecureRandom extends SecureRandom {
        @Override
        public void nextBytes(byte[] bytes) {
            throw new ProviderException("simulated RNG failure");
        }
    }
}
