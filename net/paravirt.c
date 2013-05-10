#include "net/paravirt.h"


void paravirt_configure_csb(struct paravirt_csb** csb, uint32_t csbbal,
		    uint32_t csbbah, QEMUBH* tx_bh, AddressSpace *as)
{
    hwaddr len = 4096;
    hwaddr base = ((uint64_t)csbbah << 32) | csbbal;
    /*
     * We require that writes to the CSB address registers
     * are in the order CSBBAH , CSBBAL so on the second one
     * we have a valid 64-bit memory address.
     * Any previous region is unmapped, and handlers terminated.
     * The CSB is then remapped if the new pointer is != 0
     */
    if (*csb) {
	qemu_bh_cancel(tx_bh);
	address_space_unmap(as, *csb, len, 1, len);
	*csb = NULL;
	printf("TXBH canc + CSB release\n");
    }
    if (base) {
	*csb = address_space_map(as, base, &len, 1 /* is_write */);
	printf("CSB (re)mapping\n");
    }
}
