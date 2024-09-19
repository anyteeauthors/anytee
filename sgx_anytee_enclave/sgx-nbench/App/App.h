/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#if defined(_MSC_VER)
# define TOKEN_FILENAME   "Enclave.token"
# define ENCLAVE_FILENAME "Enclave.signed.dll"
#elif defined(__GNUC__)
# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"
#endif

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif


/*Memory management*/
void app_AllocateMemory(size_t size);
void app_AllocateMemory2(size_t size);
void app_AllocateMemory3(size_t size);
void app_AllocateMemory4(size_t size);
void app_AllocateMemory5(size_t size);
void app_FreeMemory();
void app_FreeMemory2();
void app_FreeMemory3();
void app_FreeMemory4();
void app_FreeMemory5();

/*NumSort*/
void app_LoadNumArrayWithRand(unsigned long arraysize, unsigned int numarrays);
void app_NumHeapSort(unsigned long base_offset,unsigned long bottom, unsigned long top);

/*BitSort*/
unsigned long app_bitSetup(long bitfieldarraysize, long bitoparraysize);
void app_ToggleBitRun(unsigned long bit_addr, unsigned long nbits, unsigned int val);
void app_FlipBitRun(long bit_addr,long nbits); 

/*StringSort*/
unsigned long app_LoadStringArray(unsigned int numarrays, unsigned long arraysize);
void app_StrHeapSort(unsigned long oparrayOffset, unsigned long strarrayOffset, unsigned long numstrings, unsigned long bottom, unsigned long top);
void app_call_StrHeapSort(unsigned long nstrings, unsigned int numarrays, unsigned long arraysize);

/*Floating Point*/
void app_SetupCPUEmFloatArrays(unsigned long);
void app_DoEmFloatIteration(unsigned long arraysize, unsigned long loops);

/*Fourier*/
void app_DoFPUTransIteration(unsigned long arraysize);

/*Assignment*/
void app_LoadAssignArrayWithRand(unsigned long numarrays);
void app_call_AssignmentTest(unsigned int numarrays);

/*IDEAsort*/
void app_loadIDEA(unsigned long arraysize);
void app_callIDEA(unsigned long arraysize, unsigned short* Z, unsigned short* DK, unsigned long nloops);

/*Neural Net*/
void app_set_numpats(int npats);
double app_get_in_pats(int patt, int element);
void app_set_in_pats(int patt, int element, double val);
void app_set_out_pats(int patt, int element, double val);
void app_DoNNetIteration(unsigned long nloops);

/*LU Decomposition*/
void app_moveSeedArrays(unsigned long numarrays);
void app_call_lusolve(unsigned long numarrays);
void app_build_problem();

/*Huffman Decompisition*/
void app_buildHuffman(unsigned long arraysize);
void app_callHuffman(unsigned long nloops, unsigned long arraysize);


#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
