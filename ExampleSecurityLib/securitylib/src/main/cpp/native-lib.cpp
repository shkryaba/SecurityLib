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
}


/*
 * коннектимся к libart.so, если не получилось, значит что-то пошло не так,
 * ищем метод _ZTVN3art4JDWP12JdwpAdbStateE, он возвращает находится ли он под отладкой
 */


struct VT_JdwpAdbState {
    unsigned long x;
    unsigned long y;
    void *JdwpSocketState_destructor;
    void *_JdwpSocketState_destructor;
    void *Accept;
    void *showmanyc;
    void *ShutDown;
    void *ProcessIncoming;
};

extern "C"

/*
 * коннектимся к libart.so, если не получилось, значит что-то пошло не так,
 * ищем метод _ZTVN3art4JDWP12JdwpAdbStateE, он возвращает находится ли он под отладкой
 */
JNIEXPORT void JNICALL Java_com_shkryaba_securitylib_SecurityLib_JDWPfun(
        JNIEnv *env,
        jobject /* this */) {

    void *lib = dlopen("libart.so", RTLD_NOW);

    if (lib == NULL) {
        log("Error loading libart.so");
        dlerror();
    } else {

        struct VT_JdwpAdbState *vtable = (struct VT_JdwpAdbState *) dlsym(lib,
                                                                          "_ZTVN3art4JDWP12JdwpAdbStateE");

        if (vtable == 0) {
            log("Couldn't resolve symbol '_ZTVN3art4JDWP12JdwpAdbStateE'.\n");
        } else {

            log("Vtable for JdwpAdbState at: %08x\n", vtable);

            // Let the fun begin!

            unsigned long pagesize = sysconf(_SC_PAGE_SIZE);
            unsigned long page = (unsigned long) vtable & ~(pagesize - 1);

            mprotect((void *) page, pagesize, PROT_READ | PROT_WRITE);

            vtable->ProcessIncoming = vtable->ShutDown;

            // Reset permissions & flush cache

            mprotect((void *) page, pagesize, PROT_READ);
        }
    }
}

// anti ptrace

static int child_pid;

void *monitor_pid(void *) {

    int status;

    waitpid(child_pid, &status, 0);

    /* Child status should never change. */

    _exit(0); // Commit seppuku

}

void anti_debug() {

    child_pid = fork();

    if (child_pid == 0) {
        int ppid = getppid();
        int status;

        if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0) {
            waitpid(ppid, &status, 0);

            ptrace(PTRACE_CONT, ppid, NULL, NULL);

            while (waitpid(ppid, &status, 0)) {

                if (WIFSTOPPED(status)) {
                    ptrace(PTRACE_CONT, ppid, NULL, NULL);
                } else {
                    // Process has exited
                    _exit(0);
                }
            }
        }


    } else {
        pthread_t t;

        /* Start the monitoring thread */
        pthread_create(&t, NULL, monitor_pid, (void *) NULL);
    }
}

JNIEXPORT void JNICALL
Java_com_shkryaba_securitylib_SecurityLib_antidebug(JNIEnv *, jobject /* this */) {
    anti_debug();
}

/*
 * Получаем PackageManager, из него получаем PackageName, потом PackageInfo
 * Изучаем сигнатуру в виде байтов; Получаем SHA256 в виде байт массива. Нужно сравнить с эталоном
 */

JNIEXPORT jbyteArray JNICALL
Java_com_shkryaba_securitylib_SecurityLib_signature(JNIEnv *env, jobject obj) {
    jclass cls = env->GetObjectClass(obj);
    jmethodID mid = env->GetMethodID(cls, "getPackageManager",
                                     "()Landroid/content/pm/PackageManager;");
    jobject packageManager = env->CallObjectMethod(obj, mid);

    mid = env->GetMethodID(cls, "getPackageName", "()Ljava/lang/String;");//
    jstring packageName = (jstring) env->CallObjectMethod(obj, mid);

    cls = env->GetObjectClass(packageManager);
    mid = env->GetMethodID(cls, "getPackageInfo",
                           "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jint flags = 0x00000040;
    jobject packageInfo = env->CallObjectMethod(packageManager, mid, packageName, flags);

    cls = env->GetObjectClass(packageInfo);
    jfieldID fid = env->GetFieldID(cls, "signatures", "[Landroid/content/pm/Signature;");
    jobject signatures = env->GetObjectField(packageInfo, fid);

    jobject signature = env->GetObjectArrayElement((jobjectArray) signatures, 0);

    cls = env->GetObjectClass(signature);
    mid = env->GetMethodID(cls, "toByteArray", "()[B");
    jbyteArray appSig = (jbyteArray) env->CallObjectMethod(signature, mid);

    return appSig;
}
