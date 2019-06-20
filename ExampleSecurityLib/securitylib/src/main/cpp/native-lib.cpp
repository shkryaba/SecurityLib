#include <jni.h>
#include <string>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/socket.h>
#include <endian.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define log(FMT, ...) __android_log_print(ANDROID_LOG_VERBOSE, "ANTI", FMT, ##__VA_ARGS__)

/*
 * Когда приложение запускается, ему необходимо подтянуть библиотеки libart.so
 * или dalvik (если это старая версия Android до 4.4)
 * Xposed их подменяет на libxposed_art.so и заставляет приложение (захватывает исполняемый процесс
 * и из процесса запускает xposedInitLib) перехватывать java-методы, которые указаны в модуле Xposed.
 */
extern "C" JNIEXPORT jboolean JNICALL
Java_com_shkryaba_securitylib_SecurityLib_detectXposed(
        JNIEnv *env,
        jobject /* this */) {
    void *lib = dlopen("libxposed_art.so", RTLD_NOW);

    if (lib == nullptr) {
        log("Error loading libxposed_art.so");
        dlerror();
        return JNI_FALSE;
    } else {
        struct VT_JdwpAdbState *vtable = (struct VT_JdwpAdbState *) dlsym(lib, "xposedInitLib");

        if (vtable == 0) {
            log("Couldn't resolve symbol 'xposedInitLib'.\n");
            return JNI_FALSE;
        }

        log("Xposed is enabled \n", vtable);
        return JNI_TRUE;
    }

    return JNI_FALSE;
}
