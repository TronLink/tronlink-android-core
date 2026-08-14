package org.tron.metrics.reporter;

import org.junit.Assert;
import org.junit.Test;
import org.tron.BuildConfig;

import io.reactivex.disposables.Disposable;
import io.reactivex.disposables.Disposables;
import okhttp3.OkHttpClient;

public class DataUploaderTest {

    @Test
    public void plainFormatAllowed_onlyWhenDebugBuildRequestsIt() {
        Assert.assertTrue(DataUploader.isPlainFormatAllowed(true, true));
        Assert.assertFalse(DataUploader.isPlainFormatAllowed(false, true));
        Assert.assertFalse(DataUploader.isPlainFormatAllowed(true, false));
        Assert.assertFalse(DataUploader.isPlainFormatAllowed(false, false));
    }

    @Test
    public void init_appliesBuildVariantPlainFormatGate() {
        DataUploader uploader = DataUploader.getInstance();

        uploader.init(null, null, true, new OkHttpClient(), "https://example.com/");

        Assert.assertEquals(BuildConfig.DEBUG, uploader.getFormatPlain());
        uploader.release();
    }

    @Test
    public void release_disposesSubscriptionPublishedByStaleUpload() {
        DataUploader uploader = DataUploader.getInstance();
        long generation = uploader.captureSubscriptionGeneration();
        Disposable staleSubscription = Disposables.empty();

        uploader.release();
        boolean published = uploader.publishSubscription(staleSubscription, generation);

        Assert.assertFalse(published);
        Assert.assertTrue(staleSubscription.isDisposed());
    }
}
