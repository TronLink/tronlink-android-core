package org.tron.metrics.reporter;

import org.tron.BuildConfig;
import org.tron.common.utils.LogUtils;
import org.tron.metrics.bean.StatDataRequest;
import org.tron.metrics.repository.IBalanceRepository;
import org.tron.metrics.repository.ITransactionRepository;
import org.tron.metrics.utils.GsonUtils;

import java.util.concurrent.atomic.AtomicReference;

import io.reactivex.disposables.Disposable;
import io.reactivex.disposables.SerialDisposable;
import io.reactivex.schedulers.Schedulers;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import retrofit2.adapter.rxjava2.RxJava2CallAdapterFactory;
import retrofit2.converter.gson.GsonConverterFactory;

/**
 * Data upload flow manager
 */
public class DataUploader {
    private static final String TAG = "ReportLog";

    // The singleton is shared across threads (init/upload/release may be called from
    // different threads). Rather than guard each mutable field, the whole configuration
    // is published as one immutable snapshot through an AtomicReference so upload() always
    // sees a self-consistent set of dependencies (Q-01).
    private final AtomicReference<Config> configRef = new AtomicReference<>();
    // SerialDisposable atomically disposes the previous subscription when a new one is set,
    // and is safe to set/replace from any thread.
    private final SerialDisposable disposable = new SerialDisposable();
    private final Object subscriptionLock = new Object();
    private long subscriptionGeneration;

    private DataUploader() {
    }

    public static DataUploader getInstance() {
        return Holder.INSTANCE;
    }

    public void init(IBalanceRepository balanceRepository,
                     ITransactionRepository transactionCache,
                     boolean formatPlain,
                     OkHttpClient okHttpClient,
                     String baseUrl) {
        if (baseUrl == null || (!baseUrl.startsWith("https://") && !BuildConfig.DEBUG)) {
            throw new IllegalArgumentException("baseUrl must use https");
        }
        boolean effectivePlain = isPlainFormatAllowed(formatPlain, BuildConfig.DEBUG);
        configRef.set(new Config(balanceRepository, transactionCache, effectivePlain, okHttpClient, baseUrl));
    }

    static boolean isPlainFormatAllowed(boolean requestedPlain, boolean debugBuild) {
        return requestedPlain && debugBuild;
    }

    public boolean getFormatPlain() {
        Config config = configRef.get();
        return config != null && config.formatPlain;
    }

    public void upload(IUploadResultCallback iUploadResultCallback) {
        // Capture the lifecycle generation first. Any release() after this point invalidates
        // this upload, even if it happens before the immutable Config snapshot is read.
        long generation = captureSubscriptionGeneration();
        // Read a single immutable snapshot so the whole upload runs against one consistent
        // configuration even if init()/release() is called concurrently on another thread.
        Config config = configRef.get();
        // Every terminal path must signal the callback, otherwise host retry logic
        // driven by onSuccess/onFail hangs forever.
        if (config == null || config.okHttpClient == null || config.baseUrl == null) {
            notifySkipped(iUploadResultCallback, "uploader not initialized");
            return;
        }
        long startTime = System.currentTimeMillis();
        try {
            // accepted: Q-11 prepareUploadData runs on the caller thread by design; hosts
            // are expected to invoke upload() off the main thread, and Room guards main-thread
            // access via IllegalStateException (caught and logged in DataPreparationManager).
            DataPreparationManager.DataPreparationResult prepResult = DataPreparationManager.prepareUploadData(config.balanceRepository, config.transactionRepository);

            if (prepResult.isFailed()) {
                notifyFail(iUploadResultCallback, new IllegalStateException("data preparation failed"));
                return;
            }
            if (!prepResult.hasData()) {
                LogUtils.i(TAG, "No data needs to be uploaded");
                notifySkipped(iUploadResultCallback, "no data to upload");
                return;
            }

            executeNetworkRequest(config, prepResult, startTime, iUploadResultCallback, generation);
        } catch (Exception e) {
            LogUtils.e(TAG, "Data upload flow failed: " + e.getMessage());
            notifyFail(iUploadResultCallback, e);
        }
    }

    /**
     * Disposes the in-flight upload subscription. Hosts should call this on
     * logout/shutdown so late responses cannot reach a dead context.
     */
    public void release() {
        synchronized (subscriptionLock) {
            // Invalidate uploads that subscribed but have not yet published their Disposable.
            // A late publisher observes the changed generation and disposes itself.
            subscriptionGeneration++;
            disposable.set(null);
        }
    }

    long captureSubscriptionGeneration() {
        synchronized (subscriptionLock) {
            return subscriptionGeneration;
        }
    }

    boolean publishSubscription(Disposable subscription, long generation) {
        synchronized (subscriptionLock) {
            if (generation != subscriptionGeneration) {
                subscription.dispose();
                return false;
            }
            disposable.set(subscription);
            return true;
        }
    }

    private void notifySkipped(IUploadResultCallback callback, String reason) {
        if (callback == null) {
            return;
        }
        try {
            callback.onSkipped(reason);
        } catch (Throwable t) {
            if (t instanceof Error) {
                throw (Error) t;
            }
            LogUtils.e("[" + TAG + "] onSkipped handler failed", t);
        }
    }

    private void notifyFail(IUploadResultCallback callback, Throwable cause) {
        if (callback == null) {
            return;
        }
        try {
            callback.onFail(cause);
        } catch (Throwable t) {
            if (t instanceof Error) {
                throw (Error) t;
            }
            LogUtils.e("[" + TAG + "] onFail handler failed", t);
        }
    }

    private void executeNetworkRequest(Config config, DataPreparationManager.DataPreparationResult prepResult, long startTime, IUploadResultCallback iUploadResultCallback, long generation) {
        try {
            StatDataRequest statRequest = prepResult.getRequest();

            okhttp3.RequestBody requestBody = createRequestBody(statRequest);

            ReporterHttpApi api = createStatDataAPI(config);

            // SerialDisposable.set atomically disposes the previously held subscription,
            // so rapid repeated upload() calls cannot leak subscriptions.
            Disposable subscription = api.uploadStatData(requestBody).subscribeOn(Schedulers.io()).subscribe(statDataResponse -> {
                // Guard the entire onSuccess body: any exception thrown here would otherwise
                // escape the RxJava chain (RxJava2 onNext exceptions go to RxJavaPlugins, not onError).
                boolean onSuccessInvoked = false;
                try {
                    if (statDataResponse != null && statDataResponse.getData() != null) {
                        deleteCachedData(config, statDataResponse.getData().isTxt(), prepResult);
                    }

                    if (iUploadResultCallback != null) {
                        onSuccessInvoked = true;
                        iUploadResultCallback.onSuccess(statDataResponse);
                    }
                } catch (Throwable t) {
                    // Let VM-level Errors continue to propagate (OOM, StackOverflow, etc.)
                    if (t instanceof Error) {
                        throw (Error) t;
                    }
                    LogUtils.e("[" + TAG + "] onSuccess handler failed", t);
                    // Only fall back to onFail if onSuccess has not been signalled yet —
                    // otherwise the callback contract (success XOR fail) would be violated.
                    if (!onSuccessInvoked && iUploadResultCallback != null) {
                        try {
                            iUploadResultCallback.onFail(t);
                        } catch (Throwable inner) {
                            if (inner instanceof Error) {
                                throw (Error) inner;
                            }
                            LogUtils.e("[" + TAG + "] fallback onFail also threw", inner);
                        }
                    }
                }
            }, throwable -> notifyFail(iUploadResultCallback, throwable));
            // Publish only if release() has not invalidated this upload while subscribe() was
            // being created. The check and publication are linearized with release().
            publishSubscription(subscription, generation);
        } catch (Exception e) {
            LogUtils.e(TAG, "Network request exception: " + e.getMessage());
            notifyFail(iUploadResultCallback, e);
        }
    }

    private okhttp3.RequestBody createRequestBody(StatDataRequest statRequest) {
        String jsonString = GsonUtils.toGsonString(statRequest);
        return okhttp3.RequestBody.create(
                MediaType.parse("application/json; charset=utf-8"),
                jsonString
        );
    }

    private ReporterHttpApi createStatDataAPI(Config config) {
        // accepted: [Q-04] Interceptor still reads global getFormatPlain(); metrics-only
        // Config/format race, no asset path. Scan report 2026-07-14.
        okhttp3.OkHttpClient httpClient = config.okHttpClient.newBuilder()
                .addInterceptor(new DataFormatInterceptor())
                .build();

        retrofit2.Retrofit retrofit = new retrofit2.Retrofit.Builder()
                .client(httpClient)
                .baseUrl(config.baseUrl)
                .addConverterFactory(GsonConverterFactory.create())
                .addCallAdapterFactory(RxJava2CallAdapterFactory.create())
                .build();

        return retrofit.create(ReporterHttpApi.class);
    }

    private void deleteCachedData(Config config, boolean result, DataPreparationManager.DataPreparationResult prepResult) {
        try {
            if (result) {
                // Delete balance data using uploaded data
                if (prepResult.getBalanceList() != null && !prepResult.getBalanceList().isEmpty()) {
                    config.balanceRepository.updateAndDelete(prepResult.getBalanceList());
                }
                // Delete transaction data using uploaded data
                if (prepResult.getTransactionList() != null && !prepResult.getTransactionList().isEmpty()) {
                    config.transactionRepository.updateAndDeleteData(prepResult.getTransactionList());
                }
            }
        } catch (Exception e) {
            LogUtils.e(TAG, "Cache deletion failed: " + e.getMessage());
        }
    }

    /**
     * Immutable snapshot of the uploader configuration. Publishing a whole new instance
     * through {@link #configRef} guarantees upload() never observes a half-applied init().
     */
    private static final class Config {
        final IBalanceRepository balanceRepository;
        final ITransactionRepository transactionRepository;
        final boolean formatPlain;
        final OkHttpClient okHttpClient;
        final String baseUrl;

        Config(IBalanceRepository balanceRepository,
               ITransactionRepository transactionRepository,
               boolean formatPlain,
               OkHttpClient okHttpClient,
               String baseUrl) {
            this.balanceRepository = balanceRepository;
            this.transactionRepository = transactionRepository;
            this.formatPlain = formatPlain;
            this.okHttpClient = okHttpClient;
            this.baseUrl = baseUrl;
        }
    }

    private static class Holder {
        private static final DataUploader INSTANCE = new DataUploader();
    }

}
