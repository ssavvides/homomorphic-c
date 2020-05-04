#include "packing.h"


int total_packing_bits(int ptxt_bits, bool ahe) {

	int ctxt_bits = DEFAULT_KEY_LEN;
	int overflow_bits;
	if (ahe) {
		int items_per_ctxt = ctxt_bits / (ptxt_bits + PACKING_BITS);
    	overflow_bits = (ctxt_bits - items_per_ctxt * ptxt_bits) / items_per_ctxt;
	} else {
		// find number of operations allowed before overflow
		// derived from: "ptxt_bits * ops * (ops + 1) = ctxt_bits"
		int ops = (sqrt(ptxt_bits * (ptxt_bits + 4 * ctxt_bits)) - ptxt_bits) / (2 * ptxt_bits);
		overflow_bits = ptxt_bits * ops;
	}

    return overflow_bits + ptxt_bits;
}

int items_per_ctxt(int ptxt_bits, bool ahe) {
	if (ahe)
		return DEFAULT_KEY_LEN / total_packing_bits(ptxt_bits, ahe);

	// in MHE we always pack 2 items per cipher text.
	return 2;
}
