/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (C) 2009 Xtralogic, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.xtralogic.android.logcollector;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ApplicationErrorReport;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SendLogActivity extends Activity
{
    public final static String TAG = "com.xtralogic.android.logcollector";//$NON-NLS-1$

    public static final String ACTION_SEND_LOG = "com.xtralogic.logcollector.intent.action.SEND_LOG";//$NON-NLS-1$
    public static final String EXTRA_SEND_INTENT_ACTION = "com.xtralogic.logcollector.intent.extra.SEND_INTENT_ACTION";//$NON-NLS-1$
    public static final String EXTRA_DATA = "com.xtralogic.logcollector.intent.extra.DATA";//$NON-NLS-1$
    public static final String EXTRA_ADDITIONAL_INFO = "com.xtralogic.logcollector.intent.extra.ADDITIONAL_INFO";//$NON-NLS-1$
    public static final String EXTRA_SHOW_UI = "com.xtralogic.logcollector.intent.extra.SHOW_UI";//$NON-NLS-1$
    public static final String EXTRA_FILTER_SPECS = "com.xtralogic.logcollector.intent.extra.FILTER_SPECS";//$NON-NLS-1$
    public static final String EXTRA_FORMAT = "com.xtralogic.logcollector.intent.extra.FORMAT";//$NON-NLS-1$
    public static final String EXTRA_BUFFER = "com.xtralogic.logcollector.intent.extra.BUFFER";//$NON-NLS-1$

    final int MAX_LOG_MESSAGE_LENGTH = 100000;

    private AlertDialog mMainDialog;
    private Intent mSendIntent;
    private ProgressDialog mProgressDialog;
    private String mAdditonalInfo;
    private boolean mShowUi;
    private String[] mFilterSpecs;
    private String mFormat;
    private String mBuffer;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mSendIntent = null;

        Intent intent = getIntent();
        if (null != intent) {
            String action = intent.getAction();
            if (ACTION_SEND_LOG.equals(action) || Intent.ACTION_VIEW.equals(action)) {
                String extraSendAction = intent.getStringExtra(EXTRA_SEND_INTENT_ACTION);
                String crashInfo = intent.getStringExtra(Intent.ACTION_VIEW);
                crashInfo = TextUtils.isEmpty(crashInfo) ? "" : crashInfo;
                if (extraSendAction == null && null == crashInfo) {
                    Log.e(App.TAG, "Quiting, EXTRA_SEND_INTENT_ACTION is not supplied");//$NON-NLS-1$
                    finish();
                    return;
                }

                mSendIntent = new Intent(extraSendAction);

                Uri data = (Uri) intent.getParcelableExtra(EXTRA_DATA);
                if (data != null) {
                    mSendIntent.setData(data);
                }

                String[] emails = new String[] {
                        "yuanqingyun@gmail.com"
                };// intent.getStringArrayExtra(Intent.EXTRA_EMAIL);

                if (emails != null) {
                    mSendIntent.putExtra(Intent.EXTRA_EMAIL, emails);
                }

                String[] ccs = intent.getStringArrayExtra(Intent.EXTRA_CC);
                if (ccs != null) {
                    mSendIntent.putExtra(Intent.EXTRA_CC, ccs);
                }

                String[] bccs = intent.getStringArrayExtra(Intent.EXTRA_BCC);
                if (bccs != null) {
                    mSendIntent.putExtra(Intent.EXTRA_BCC, bccs);
                }

                String subject = intent.getStringExtra(Intent.EXTRA_SUBJECT);
                if (subject != null) {
                    mSendIntent.putExtra(Intent.EXTRA_SUBJECT, subject);
                }

                mAdditonalInfo = intent.getStringExtra(EXTRA_ADDITIONAL_INFO);
                if (crashInfo != null) {
                    mAdditonalInfo += crashInfo.toString();
                }
                mShowUi = intent.getBooleanExtra(EXTRA_SHOW_UI, false);
                mFilterSpecs = intent.getStringArrayExtra(EXTRA_FILTER_SPECS);
                mFormat = intent.getStringExtra(EXTRA_FORMAT);
                mBuffer = intent.getStringExtra(EXTRA_BUFFER);
            }
        }

        if (null == mSendIntent) {
            // standalone application
            mShowUi = true;
            mSendIntent = new Intent(Intent.ACTION_SEND);
            mSendIntent.putExtra(Intent.EXTRA_EMAIL, new String[] {
                    "yuanqingyun@gmail.com"
            });
            mSendIntent.putExtra(Intent.EXTRA_SUBJECT, getString(R.string.message_subject));
            //mSendIntent.setType("text/plain");//$NON-NLS-1$

            mAdditonalInfo = getString(R.string.device_info_fmt, getVersionNumber(this),
                    Build.MODEL, Build.VERSION.RELEASE, getFormattedKernelVersion(), Build.DISPLAY);
            if (mAdditonalInfo != null) {
                mSendIntent.putExtra("body", mAdditonalInfo);
            }
            mFormat = "time";
        }

        if (mShowUi) {
            mMainDialog = new AlertDialog.Builder(this)
                    .setTitle(getString(R.string.app_name))
                    .setMessage(getString(R.string.main_dialog_text))
                    .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int whichButton) {
                            collectAndSendLog();
                        }
                    })
                    .setNegativeButton(android.R.string.cancel,
                            new DialogInterface.OnClickListener() {
                                public void onClick(DialogInterface dialog, int whichButton) {
                                    finish();
                                }
                            })
                    .show();
        }
        else {
            collectAndSendLog();
        }
    }

    @SuppressWarnings("unchecked")
    void collectAndSendLog() {
        String logFile = "/mnt/sdcard/logs.tar.bz2";
        DataOutputStream os = null;
        DataInputStream is = null;
        Process process = null;
        try {
            process = Runtime
                    .getRuntime()
                    .exec("su");
            // BufferedReader bufferedReader = new BufferedReader(new
            // InputStreamReader(process.getInputStream()));
            os = new DataOutputStream(process.getOutputStream());
            // is = new DataInputStream(process.getInputStream());
            os.writeBytes("logcat -v time -d > /tmp/logcat.txt\n");
            os.writeBytes("dmesg > /tmp/dmesg.txt\n");
            os.writeBytes("tar -cjf " + logFile + " /tmp/dmesg.txt /tmp/logcat.txt\n");
            os.writeBytes("rm -f /tmp/dmesg.txt /tmp/logcat.txt\n");
            os.writeBytes("exit\n");
            os.flush();
            process.waitFor();
        } catch (Exception e) {
            Log.e(App.TAG, "collectAndSendLog failed", e);
            showErrorDialog(getString(R.string.failed_to_get_log_message));
            return;
        } finally {
            try {
                if (os != null) {
                    os.close();
                }
                if (is != null) {
                    is.close();
                }
                process.destroy();
            } catch (Exception e) {
                Log.e(App.TAG, "collectAndSendLog failed", e);//$NON-NLS-1$
            }
        }

        File file = new File(logFile);
        mSendIntent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(file));
        mSendIntent.setType("application/x-bzip-compressed-tar");

        startActivity(Intent.createChooser(mSendIntent, getString(R.string.chooser_title)));
        finish();
    }

    void showErrorDialog(String errorMessage) {
        new AlertDialog.Builder(this)
                .setTitle(getString(R.string.app_name))
                .setMessage(errorMessage)
                .setIcon(android.R.drawable.ic_dialog_alert)
                .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        finish();
                    }
                })
                .show();
    }

    void dismissMainDialog() {
        if (null != mMainDialog && mMainDialog.isShowing()) {
            mMainDialog.dismiss();
            mMainDialog = null;
        }
    }

    @Override
    protected void onPause() {
        dismissMainDialog();

        super.onPause();
    }

    private static String getVersionNumber(Context context)
    {
        String version = "?";
        try
        {
            PackageInfo packagInfo = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0);
            version = packagInfo.versionName;
        } catch (PackageManager.NameNotFoundException e) {
        }
        ;

        return version;
    }

    private String getFormattedKernelVersion()
    {
        String procVersionStr;

        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/version"), 256);
            try {
                procVersionStr = reader.readLine();
            } finally {
                reader.close();
            }

            final String PROC_VERSION_REGEX =
                    "\\w+\\s+" + /* ignore: Linux */
                            "\\w+\\s+" + /* ignore: version */
                            "([^\\s]+)\\s+" + /* group 1: 2.6.22-omap1 */
                            "\\(([^\\s@]+(?:@[^\\s.]+)?)[^)]*\\)\\s+" + /*
                                                                         * group
                                                                         * 2:
                                                                         * (xxxxxx
                                                                         * @
                                                                         * xxxxx
                                                                         * .
                                                                         * constant
                                                                         * )
                                                                         */
                            "\\([^)]+\\)\\s+" + /* ignore: (gcc ..) */
                            "([^\\s]+)\\s+" + /* group 3: #26 */
                            "(?:PREEMPT\\s+)?" + /* ignore: PREEMPT (optional) */
                            "(.+)"; /* group 4: date */

            Pattern p = Pattern.compile(PROC_VERSION_REGEX);
            Matcher m = p.matcher(procVersionStr);

            if (!m.matches()) {
                Log.e(TAG, "Regex did not match on /proc/version: " + procVersionStr);
                return "Unavailable";
            } else if (m.groupCount() < 4) {
                Log.e(TAG, "Regex match on /proc/version only returned " + m.groupCount()
                        + " groups");
                return "Unavailable";
            } else {
                return (new StringBuilder(m.group(1)).append("\n").append(
                        m.group(2)).append(" ").append(m.group(3)).append("\n")
                        .append(m.group(4))).toString();
            }
        } catch (IOException e) {
            Log.e(TAG,
                    "IO Exception when getting kernel version for Device Info screen",
                    e);

            return "Unavailable";
        }
    }
}
