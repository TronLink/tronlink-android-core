package org.tron.metrics.utils;

import org.junit.Assert;
import org.junit.Test;
import org.tron.metrics.bean.BalanceCacheEntity;
import org.tron.metrics.bean.StatXData;

import java.util.Collections;
import java.util.List;

public class StatDataConverterTest {

    @Test
    public void convertBalanceCacheToStatXData_formatsAllBalanceReportNumbers() {
        BalanceCacheEntity entity = new BalanceCacheEntity();
        entity.setUId("uid-1");
        entity.setIdType(0);
        entity.setTrxBalance("1234.56");
        entity.setUsdtBalance("0.123456");
        entity.setUsdBalance("99.999");
        entity.setDay("2026-07-06");

        List<StatXData> result = StatDataConverter.convertBalanceCacheToStatXData(
                Collections.singletonList(entity));

        Assert.assertEquals(1, result.size());
        Assert.assertEquals("1230", result.get(0).getTrxBalance());
        Assert.assertEquals("0.1", result.get(0).getUsdtBalance());
        Assert.assertEquals("99.9", result.get(0).getUsdBalance());
    }

    @Test
    public void formatReportNumber_matchesThreeSignificantDigitsThenOneDecimalPlace() {
        Assert.assertEquals("1230", StatDataConverter.formatReportNumber("1234.56"));
        Assert.assertEquals("123", StatDataConverter.formatReportNumber("123.456"));
        Assert.assertEquals("12.3", StatDataConverter.formatReportNumber("12.3456"));
        Assert.assertEquals("1.2", StatDataConverter.formatReportNumber("1.23456"));
        Assert.assertEquals("1", StatDataConverter.formatReportNumber("1.09"));
        Assert.assertEquals("0.1", StatDataConverter.formatReportNumber("0.123456"));
        Assert.assertEquals("0", StatDataConverter.formatReportNumber("0.0123456"));
    }

    @Test
    public void formatReportNumber_invalidOrEmptyValue_returnsZero() {
        Assert.assertEquals("0", StatDataConverter.formatReportNumber(null));
        Assert.assertEquals("0", StatDataConverter.formatReportNumber(""));
        Assert.assertEquals("0", StatDataConverter.formatReportNumber("   "));
        Assert.assertEquals("0", StatDataConverter.formatReportNumber("abc"));
        Assert.assertEquals("0", StatDataConverter.formatReportNumber("NaN"));
        Assert.assertEquals("0", StatDataConverter.formatReportNumber("Infinity"));
    }
}
