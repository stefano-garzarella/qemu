/*
 * Copyright (C) 2013 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Support routines for paravirtualized network interfaces.
 */

#include "hw/pci/pci.h"  /* AddressSpace */

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
