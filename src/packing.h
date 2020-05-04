#ifndef PACKING_H
#define PACKING_H

#define PACKING_BITS 30

#include "pk.h"
#include <math.h>
#include <stdbool.h>

int total_packing_bits(int ptxt_bits, bool ahe);
int items_per_ctxt(int ptxt_bits, bool ahe);

#endif
