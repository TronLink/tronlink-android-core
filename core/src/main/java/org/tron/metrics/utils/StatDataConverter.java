package org.tron.metrics.utils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.tron.common.utils.LogUtils;
import org.tron.metrics.bean.BalanceCacheEntity;
import org.tron.metrics.bean.StatXData;
import org.tron.metrics.bean.StatYData;
import org.tron.metrics.bean.TransactionCacheEntity;
import org.tron.metrics.reporter.ReportStatConfig;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Data conversion utility class
 */
public class StatDataConverter {

    private static final String TAG = ReportStatConfig.LOG_TAG + "_Converter";
    private static final MathContext REPORT_NUMBER_PRECISION =
            new MathContext(3, RoundingMode.DOWN);

    private static boolean isEmpty(List<?> list) {
        return list == null || list.isEmpty();
    }

    public static List<StatXData> convertBalanceCacheToStatXData(List<BalanceCacheEntity> balanceList) {
        if (isEmpty(balanceList)) {
            return new ArrayList<>();
        }

        List<StatXData> xDataList = new ArrayList<>();

        for (BalanceCacheEntity entity : balanceList) {
            StatXData xData = new StatXData();
            xData.setUId(entity.getUId());
            xData.setIdType(String.valueOf(entity.getIdType()));
            xData.setTrxBalance(formatReportNumber(entity.getTrxBalance()));
            xData.setUsdtBalance(formatReportNumber(entity.getUsdtBalance()));
            xData.setUsdBalance(formatReportNumber(entity.getUsdBalance()));
            xData.setDay(entity.getDay());
            xDataList.add(xData);
        }

        return xDataList;
    }

    public static List<StatYData> convertTransactionCacheToStatYData(List<TransactionCacheEntity> transactionList) {
        if (isEmpty(transactionList)) {
            return new ArrayList<>();
        }

        List<StatYData> yDataList = new ArrayList<>();

        for (TransactionCacheEntity entity : transactionList) {
            StatYData yData = new StatYData();
            yData.setUId(entity.getUId());
            yData.setIdType(String.valueOf(entity.getIdType()));
            yData.setActionType(String.valueOf(entity.getActionType()));
            yData.setCount(String.valueOf(entity.getCount()));
            yData.setTokenAddress(entity.getTokenAddress());
            yData.setTokenAmount(entity.getTokenAmount());
            yData.setEnergy(entity.getEnergy());
            yData.setBandwidth(entity.getBandwidth());
            yData.setBurn(entity.getBurn());
            yData.setDay(entity.getDay());
            yData.setAmountDistribution(formatDistribution(entity.getDistribution()));
            yDataList.add(yData);
        }

        return yDataList;
    }

    public static String buildXDataString(List<StatXData> xDataList) {
        if (isEmpty(xDataList)) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        for (StatXData data : xDataList) {
            appendVersionAndField(sb, ReportStatConfig.VERSION_X, data.getUId());
            appendField(sb, data.getIdType());
            appendField(sb, data.getTrxBalance());
            appendField(sb, data.getUsdtBalance());
            appendField(sb, data.getUsdBalance());
            appendField(sb, data.getDay());
        }

        return sb.toString();
    }

    public static String buildYDataString(List<StatYData> yDataList) {
        if (isEmpty(yDataList)) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        for (StatYData data : yDataList) {
            appendVersionAndField(sb, ReportStatConfig.VERSION_Y, data.getUId());
            appendField(sb, data.getIdType());
            appendField(sb, data.getActionType());
            appendField(sb, data.getCount());
            appendField(sb, data.getTokenAddress());
            appendField(sb, data.getTokenAmount());
            appendField(sb, data.getEnergy());
            appendField(sb, data.getBandwidth());
            appendField(sb, data.getBurn());
            appendField(sb, data.getDay());
            appendField(sb, data.getAmountDistribution());
        }

        return sb.toString();
    }

    public static String formatReportNumber(String value) {
        if (value == null || value.trim().isEmpty()) {
            return "0";
        }
        try {
            return new BigDecimal(value)
                    .round(REPORT_NUMBER_PRECISION)
                    .setScale(1, RoundingMode.DOWN)
                    .stripTrailingZeros()
                    .toPlainString();
        } catch (NumberFormatException e) {
            return "0";
        }
    }

    public static String encryptDataWithTs(String data, String ts, String signature) {
        if (data == null || data.isEmpty()) {
            return "";
        }

        try {
            String keyBase64 = CryptoUtils.generateKeyFromTs(ts, signature);
            if (keyBase64 == null) {
                LogUtils.e(TAG, "encryptDataWithTs failed: key derivation returned null");
                return "";
            }

            String encryptedData = CryptoUtils.encrypt(data, keyBase64);
            return encryptedData;
        } catch (Exception e) {
            // Log the root cause (never the cleartext data); upstream treats "" as an
            // encryption failure and aborts the upload, so no cleartext is leaked.
            LogUtils.e(TAG, "encryptDataWithTs failed: " + e.getMessage());
            return "";
        }
    }


    private static void appendField(StringBuilder sb, String value) {
        String fieldValue = (value != null && !value.isEmpty()) ? value : "_";
        sb.append(fieldValue).append(ReportStatConfig.FIELD_SEPARATOR);
    }

    private static void appendVersionAndField(StringBuilder sb, String version, String value) {
        sb.append(version).append(ReportStatConfig.FIELD_SEPARATOR);
        appendField(sb, value);
    }

    private static String formatDistribution(String distributionJson) {
        try {
            Map<String, Integer> map = changeGsonToMap(distributionJson);
            return map == null ? "" : String.join(",",
                                                  map.entrySet().stream()
                                                          .map(entry -> entry.getKey() + ":" + entry.getValue())
                                                          .toArray(String[]::new));
        } catch (Exception e) {
            // Malformed distribution JSON: log the root cause so dropped data is traceable,
            // then degrade to an empty field (consistent with encryptDataWithTs handling).
            LogUtils.e(TAG, "formatDistribution failed: " + e.getMessage());
            return "";
        }
    }

    private static Map<String, Integer> changeGsonToMap(String gsonString) {
        return new Gson().fromJson(gsonString, new TypeToken<Map<String, Integer>>() {
        }.getType());
    }
}
