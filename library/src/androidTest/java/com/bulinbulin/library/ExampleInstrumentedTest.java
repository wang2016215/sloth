package com.bulinbulin.library;

import android.content.Context;
import android.util.Log;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import com.bulinbulin.security.KeyPairInfo;
import com.bulinbulin.security.SecurityUtil;

import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void useAppContext() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        assertEquals("com.bulinbulin.library.test", appContext.getPackageName());


        KeyPairInfo keyPairInfo = new SecurityUtil().createKeyPair();

        Log.d("puk->",keyPairInfo.getPubk());

        Log.d("pri->",keyPairInfo.getPrik());


    }
}
