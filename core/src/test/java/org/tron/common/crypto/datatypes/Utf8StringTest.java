package org.tron.common.crypto.datatypes;

import org.junit.Assert;
import org.junit.Test;

/** Q-03 regression: Utf8String must reject null at construction, not blow up later. */
public class Utf8StringTest {

    @Test(expected = NullPointerException.class)
    public void constructor_nullValue_throwsImmediately() {
        new Utf8String(null);
    }

    @Test
    public void bytes32PaddedLength_emptyString_returnsOneWord() {
        Assert.assertEquals(Type.MAX_BYTE_LENGTH, new Utf8String("").bytes32PaddedLength());
    }

    @Test
    public void bytes32PaddedLength_nonEmptyString_returnsTwoWords() {
        Assert.assertEquals(2 * Type.MAX_BYTE_LENGTH, new Utf8String("abc").bytes32PaddedLength());
    }
}
