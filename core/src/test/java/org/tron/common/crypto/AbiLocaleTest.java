package org.tron.common.crypto;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.tron.common.crypto.datatypes.AbiTypes;
import org.tron.common.crypto.datatypes.DynamicArray;
import org.tron.common.crypto.datatypes.Type;
import org.tron.common.crypto.datatypes.generated.Int256;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;

/**
 * Regression tests for Q-03: under tr_TR (and az) the default-locale
 * toLowerCase() maps "I" to the dotless "ı", turning "Int256" into "ınt256"
 * and corrupting ABI type names and method selectors built from them.
 */
public class AbiLocaleTest {

    private Locale defaultLocale;

    @Before
    public void forceTurkishLocale() {
        defaultLocale = Locale.getDefault();
        Locale.setDefault(new Locale("tr", "TR"));
    }

    @After
    public void restoreLocale() {
        Locale.setDefault(defaultLocale);
    }

    @Test
    public void getSimpleTypeName_signedInt_isLocaleIndependent() {
        Assert.assertEquals("int256", Utils.getSimpleTypeName(Int256.class));
    }

    @Test
    public void getTypeAString_signedInt_isLocaleIndependent() {
        Assert.assertEquals("int256", AbiTypes.getTypeAString(Int256.class));
    }

    @Test
    public void primitiveType_int_isLocaleIndependent() {
        Assert.assertEquals(
                "int",
                new org.tron.common.crypto.datatypes.primitive.Int(1).getTypeAsString());
    }

    @Test
    public void methodSignatureAndSelector_signedIntArray_isLocaleIndependent() {
        DynamicArray<Int256> array =
                new DynamicArray<>(Int256.class, new Int256(BigInteger.ONE));
        String signature =
                FunctionEncoder.buildMethodSignature(
                        "foo", Arrays.<Type>asList(new Int256(BigInteger.ONE), array));
        // Pre-fix this came out as "foo(int256,ınt256[])" under tr_TR.
        Assert.assertEquals("foo(int256,int256[])", signature);
        Assert.assertEquals(
                FunctionEncoder.buildMethodId("foo(int256,int256[])"),
                FunctionEncoder.buildMethodId(signature));
    }
}