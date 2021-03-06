/*
 * Dispatcher.h
 *
 *  Created on: Mar 20, 2014
 *      Author: flowcoaster2
 */

#ifndef DISPATCHER_H_
#define DISPATCHER_H_

bool initDispatcher(const char* filename, bool forceStart);
void setJniEnv(JNIEnv* env);
void shutdownDispatcher();
int32_t dvmAddTaintgrindLib(const char* filename);
int32_t dvmAddTaintgrindFunc(const char* func, int32_t libRef);
int32_t dvmChangeFunc(int32_t oldHandle, int32_t newHandle);
void dvmTaintCallMethod(void* pEnv, ClassObject* clazz, const Method* method, const u4* argv, JValTaint* pReturn, u4 threadId);
//void* handleCallbacks(void* unused);

#endif /* DISPATCHER_H_ */
