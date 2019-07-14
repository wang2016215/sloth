package com.example.myapplication;

import android.util.Log;


public class TimeUtil {

    public static final String TAG = "TimeLog";

    public static void timeLog(String phase, long startTime) {
            Log.w(TAG, "【"+ Thread.currentThread().getName()+"】"+phase + "|" + (System.currentTimeMillis() - startTime));
    }

    public static void timeLog(String phase, String subPhase, long startTime) {
            Log.w(TAG, "【"+ Thread.currentThread().getName()+"】"+phase + "|" + subPhase + "|" + (System.currentTimeMillis() - startTime));
    }
}
