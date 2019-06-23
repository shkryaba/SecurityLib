package com.shkryaba.securitylib;

import android.app.ActivityManager;
import android.os.Build;

import java.io.File;
import java.util.List;

public class RootCheck {

    // Ищем su в PATH
    public static boolean checkRoot() {
        for(String pathDir : System.getenv("PATH").split(":")){
            if(new File(pathDir, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    // Проверяем есть ли packagname в котором содержится supersu
    public boolean checkRunningProcesses(ActivityManager manager) {
        boolean returnValue = false;
        List<ActivityManager.RunningServiceInfo> list = manager.getRunningServices(300);

        if(list != null){
            String tempName;
            for(int i=0;i<list.size();++i){
                tempName = list.get(i).process;

                if(tempName.contains("supersu") || tempName.contains("superuser")){
                    returnValue = true;
                }
            }
        }

        return returnValue;
    }

    // В эмуляторах есть ключевые слова test-keys и userdebug
    private boolean isTestKeyBuild() {
        String str = Build.TAGS;
        return (str != null) && (str.contains("test-keys") || str.contains("userdebug"));
    }
}
