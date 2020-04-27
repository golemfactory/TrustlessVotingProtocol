#ifndef TVP_VOTER_H
#define TVP_VOTER_H

#include <stddef.h>

int v_parse_vdeh(const void* vdeh, size_t vdeh_size, const void* eh_pubkey, size_t eh_pubkey_size);

#endif /* TVP_VOTER_H */
