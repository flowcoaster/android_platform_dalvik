/*
 * Dispatcher.cpp
 *
 *  Created on: Mar 20, 2014
 *      Author: flowcoaster2
 */

#include "Dalvik.h"
#include <pthread.h>
#include <stdlib.h>
#include "dlfcn.h"

#define LOG_TAG "Dalvik Dispatcher"

#ifndef TAINT_JNI_LOG
	#define ALOGD(...) void();
#endif

void setJniEnv(JNIEnv* jnienv) {
	ALOGD("in Dalvik: setJniEnv(%p)", jnienv);
	if (gDvm.setEnv != 0) {
		gDvm.setEnv(jnienv);
	} else ALOGD("Warning: could not call SetJniEnv because dispatcher is not initialized.");
}

bool initDispatcher(const char* filename, bool forceStart) {
	ALOGD("initDispatcher(filename=%s, forceStart=%d)", filename, forceStart);
    Thread* self = dvmThreadSelf();
    ThreadStatus oldStatus = dvmChangeStatus(self, THREAD_VMWAIT);
    gDvm.dispatcherHandle = dlopen(filename, RTLD_LAZY);
    //gDvm.dispatcherHandle = dlopen("dispatcher.so", RTLD_LAZY);
    //gDvm.dispatcherHandle = dlopen("/data/app-lib/com.example.hellojni-1/libhello-jni.so", RTLD_LAZY);
    dvmChangeStatus(self, oldStatus);

    char** detail;
    if (gDvm.dispatcherHandle == NULL) {
        *detail = strdup(dlerror());
        ALOGE("dlopen(\"%s\") failed: %s", filename, *detail);
        return false;
    } else
    	ALOGD("dlopen success");

    gDvm.initDispatcher = (init_tt) dlsym(gDvm.dispatcherHandle, "initDispatcher");
    const char* dlsym_error = dlerror();
    if (dlsym_error) ALOGW("Cannot load symbol 'initDispatcher': %s", dlsym_error);
    gDvm.wrapperInitialized = gDvm.initDispatcher(forceStart);
    gDvm.setEnv = (setEnv_tt) dlsym(gDvm.dispatcherHandle, "setEnv");
    dlsym_error = dlerror();
    if (dlsym_error) ALOGW("Cannot load symbol 'setEnv': %s", dlsym_error);
	if (gDvm.serviceEnv != 0) gDvm.setEnv(gDvm.serviceEnv);
    gDvm.addLib = (addLib_tt) dlsym(gDvm.dispatcherHandle, "addLib");
    dlsym_error = dlerror();
    if (dlsym_error) ALOGW("Cannot load symbol 'addLib': %s", dlsym_error);
    gDvm.addFunc = (addFunc_tt) dlsym(gDvm.dispatcherHandle, "addFunc");
    dlsym_error = dlerror();
    if (dlsym_error) ALOGW("Cannot load symbol 'addFunc': %s", dlsym_error);
    gDvm.taintCall = (taintCall_tt) dlsym(gDvm.dispatcherHandle, "taintCallMethod");
    dlsym_error = dlerror();
    if (dlsym_error) ALOGW("Cannot load symbol 'taintCallMethod': %s", dlsym_error);
    gDvm.changeFunc = (changeFunc_tt) dlsym(gDvm.dispatcherHandle, "changeFunc");
    dlsym_error = dlerror();
    if (dlsym_error) ALOGW("Cannot load symbol 'changeFunc': %s", dlsym_error);
    //testFunc(0,0,5,6);
	/*pthread_t tid = 0;
	int err = pthread_create(&tid, 0, &handleCallbacks, 0);
	if (err != 0)
		ALOGD("cannot create thread: %s", strerror(err));
	else
		ALOGD("Thread %ld created successfully to wait for callbacks from Wrapper", tid);*/
	
    ALOGD(" <- initDispatcher()");

    return true;
}

int32_t dvmAddTaintgrindLib(const char* filename) {
    ALOGD("dvmAddTaintgrindLib(filename=%s)", filename);
    if (gDvm.dispatcherHandle != 0) {
	int32_t result = gDvm.addLib(filename);
	ALOGD(" -> %d", result);
	return result;
    } else
	ALOGW("Warning: Dispatcher not initialized! Could not load library for native taint tracking.");
    return 0;
}

int32_t dvmAddTaintgrindFunc(const char* func, int32_t libRef) {
    ALOGD("dvmAddTaintgrindFunc(func=%s, libRef=%d)", func, libRef);
    if (gDvm.dispatcherHandle != 0) {
	int32_t result = gDvm.addFunc(func, libRef);
	ALOGD(" -> %d", result);
	return result;
    } else
	ALOGW("Warning: Dispatcher not initialized! Could not load library for native taint tracking.");
    return 0;
}

void dvmTaintCallMethod(void* pEnv, ClassObject* clazz, const Method* method, const u4* argv, JValTaint* pReturn) {
    ALOGD("-> dvmTaintCallMethod(pEnv=%08x, clazz=%08x, argInfo=%d, argc=%d, argv=%p, shorty=%s, func, pReturn)",
	(int)pEnv, (int)clazz, method->jniArgInfo, method->insSize, argv, method->shorty);
    const u4* taints = (u4*) &argv[method->insSize+1];
    //for (int i=0; i<method->insSize; i++) ALOGD("taints[%d]=%08x", i, taints[i]);
    //for (int i=0; i<=method->insSize*2; i++) ALOGD("argv[%d]=%08x", i, argv[i]);
    if (gDvm.dispatcherHandle != 0) {
	JValTaint* pResult = gDvm.taintCall(pEnv, clazz, method->jniArgInfo, method->insSize, taints, argv, method->shorty, method->tgLibHandle, method->tgFuncHandle, method->name);
	pReturn->val.j = pResult->val.j;
	pReturn->taint = pResult->taint;
	ALOGD(" <- dvmTaintCallMethod() pReturn=%lld(long)=%d(int) (taint=%d)",
	    pReturn->val.j, pReturn->val.i, pResult->taint);
    } else {
	ALOGW("Warning: Dispatcher not initialized! Could not call native taint tracking.");
	dvmPlatformInvoke(pEnv, clazz, method->jniArgInfo, method->insSize, argv, method->shorty, (void*)method->insns, &pReturn->val);
    }
}

int32_t dvmChangeFunc(int32_t oldHandle, int32_t newHandle) {
	ALOGD("dvmChangeFunc(oldHandle=%08x, newHandle=%08x)", oldHandle, newHandle);
    if (gDvm.dispatcherHandle != 0) {
		int32_t result = gDvm.changeFunc(oldHandle, newHandle);
		ALOGD(" -> %d", result);
		return result;
    } else
		ALOGW("Warning: Dispatcher not initialized! Could not load library for native taint tracking.");
    return 0;
}

/*void* handleCallbacks(void* unused) {
	gDvm.callback();
	return 0;
}*/

void shutdownDispatcher() {
	dlclose(gDvm.dispatcherHandle);
}

