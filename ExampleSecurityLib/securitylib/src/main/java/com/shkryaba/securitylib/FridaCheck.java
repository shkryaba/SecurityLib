package com.shkryaba.securitylib;


import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class FridaCheck {

    // Ищем frida (библиотека для динамического анализа приложений) в процессах Android
    public boolean checkRunningProcesses() {

        boolean returnValue = false;

        try {
            // получаем все процессы в Android
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            int read;
            char[] buffer = new char[4096];
            StringBuffer output = new StringBuffer();
            while ((read = reader.read(buffer)) > 0) {
                output.append(buffer, 0, read);
            }
            reader.close();

            // Waits for the command to finish.
            process.waitFor();

            if (output.toString().contains("frida-server")) {
                Log.d("fridaserver", "Frida Server process found!");
                returnValue = true;
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        return returnValue;
    }
}


