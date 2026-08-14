package org.tron.metrics.reporter;

import org.tron.common.utils.LogUtils;
import org.tron.metrics.bean.StatDataRequest;
import org.tron.metrics.utils.GsonUtils;
import org.tron.metrics.utils.StatDataConverter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okio.Buffer;

/**
 * Interceptor for data encryption using ts and signature from signed requests
 */
public class DataFormatInterceptor implements Interceptor {
    private static final String TAG = "DataFormatInterceptor";

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();

        RequestBody originalBody = request.body();
        if (originalBody == null || !isStatDataRequest(request)) {
            return chain.proceed(request);
        }

        // accepted: [Q-04] Metrics-only race between upload Config snapshot and global
        // formatPlain; worst case is plaintext stats or encrypt retry, no asset path.
        // Scan report 2026-07-14.
        if (DataUploader.getInstance().getFormatPlain()) {
            // Plain mode - no encryption needed
            return chain.proceed(request);
        }

        // Past this point we are in non-plain mode and encryption is mandatory.
        // If the signing metadata (ts / signature) is missing or encryption fails,
        // we MUST abort the upload (throw IOException) rather than silently sending
        // the statistics payload in cleartext. Aborting keeps the cached data intact
        // (onSuccess/deleteCachedData never runs), so it is retried on the next cycle.
        String ts = request.header("ts");
        if (ts == null || ts.isEmpty()) {
            LogUtils.e(TAG, "stat upload aborted: missing 'ts' header, cannot encrypt payload");
            throw new IOException("stat upload aborted: missing 'ts' header");
        }

        String signature = request.url().queryParameter("signature");
        if (signature == null || signature.isEmpty()) {
            LogUtils.e(TAG, "stat upload aborted: missing 'signature' query param, cannot encrypt payload");
            throw new IOException("stat upload aborted: missing 'signature' query param");
        }

        Buffer buffer = new Buffer();
        originalBody.writeTo(buffer);
        String originalJson = buffer.readString(StandardCharsets.UTF_8);

        StatDataRequest originalStatRequest = GsonUtils.gsonToBean(originalJson, StatDataRequest.class);
        if (originalStatRequest == null) {
            LogUtils.e(TAG, "stat upload aborted: failed to parse stat request body, cannot encrypt payload");
            throw new IOException("stat upload aborted: unparseable stat request body");
        }

        StatDataRequest encryptedStatRequest = new StatDataRequest();

        try {
            if (originalStatRequest.getX() != null && !originalStatRequest.getX().isEmpty()) {
                String encryptedXData = StatDataConverter.encryptDataWithTs(originalStatRequest.getX(), ts, signature);
                // encryptDataWithTs swallows errors and returns "" — treat an empty
                // result for non-empty input as an encryption failure, not as data to send.
                if (encryptedXData == null || encryptedXData.isEmpty()) {
                    throw new IOException("stat upload aborted: X data encryption failed");
                }
                encryptedStatRequest.setX(encryptedXData);
            }

            if (originalStatRequest.getY() != null && !originalStatRequest.getY().isEmpty()) {
                String encryptedYData = StatDataConverter.encryptDataWithTs(originalStatRequest.getY(), ts, signature);
                if (encryptedYData == null || encryptedYData.isEmpty()) {
                    throw new IOException("stat upload aborted: Y data encryption failed");
                }
                encryptedStatRequest.setY(encryptedYData);
            }
        } catch (IOException e) {
            // Well-formed abort signal: log and rethrow, never fall back to cleartext.
            LogUtils.e(TAG, e.getMessage() + " (ts=" + ts + ")");
            throw e;
        } catch (Exception e) {
            // Any unexpected encryption error must NOT fall back to sending cleartext.
            LogUtils.e(TAG, "encrypt failed, aborting upload (no cleartext fallback): ts=" + ts
                    + ", err=" + e.getMessage());
            throw new IOException("stat upload aborted: encryption error", e);
        }

        String encryptedJson = GsonUtils.toGsonString(encryptedStatRequest);

        RequestBody encryptedBody = RequestBody.create(
                MediaType.parse("application/json; charset=utf-8"),
                encryptedJson
        );

        Request finalRequest = request.newBuilder()
                .method(request.method(), encryptedBody)
                .build();

        return chain.proceed(finalRequest);
    }

    private boolean isStatDataRequest(Request request) {
        return request.url().toString().contains("api/stat/some");
    }
}
