#ifndef TEE_H_
#define TEE_H_

#include <bao.h>
#include <vm.h>

#define SBI_EXTID_TEE (0x544545)

int64_t sdtz_handler_setup(struct vm *vm);

#endif /* TEE_H_ */
