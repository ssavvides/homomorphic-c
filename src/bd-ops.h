#ifndef _BD_OP_H_
#define _BD_OP_H_

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "bigd.h"
#include "bigdRand.h"

void bd_L(BIGD res, const BIGD u, const BIGD n);
void bd_crt_exponentiation(BIGD result, const BIGD base,
                           const BIGD exp_p, const BIGD exp_q, const BIGD pinvq,
                           const BIGD p, const BIGD q);

void bd_prime(BIGD prime, int len);
void bd_rand(BIGD rnd, int range, bool can_be_zero);

void int_to_bd(BIGD res, int number);
void bd_to_long(long* res, BIGD number);

#endif
