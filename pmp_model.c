/*
 * A small, executable model of RISC-V PMP access checking.
 *
 * It mirrors the structure of the E906 RTL:
 *   - address match (OFF / TOR / NA4 / NAPOT)
 *   - lowest-numbered matching entry wins
 *   - R/W/X check for S/U
 *   - M-mode bypasses unlocked entries, but locked (L=1) entries apply to M too
 *   - no matching entry: M allowed, S/U denied
 *
 * Simplification: pmpaddr is kept as "physical address >> 2" (the spec's
 * encoding), instead of the E906's 26-bit PA[31:6] slice. The comparison
 * logic is the same; only the bit slicing differs.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define PMP_R 0x01u
#define PMP_W 0x02u
#define PMP_X 0x04u
#define PMP_A_SHIFT 3
#define PMP_A_MASK (3u << PMP_A_SHIFT)
#define PMP_L 0x80u

enum { A_OFF = 0, A_TOR = 1, A_NA4 = 2, A_NAPOT = 3 };
enum { PRV_U = 0, PRV_S = 1, PRV_M = 3 };
enum { ACC_LOAD, ACC_STORE, ACC_FETCH };

typedef struct {
    uint64_t pmpaddr; /* PA >> 2, as in the privileged spec */
    uint8_t cfg;
} pmp_entry;

static unsigned trailing_ones(uint64_t x)
{
    unsigned n = 0;
    while (n < 64 && (x & 1u)) {
        n++;
        x >>= 1;
    }
    return n;
}

/* Build a NAPOT pmpaddr for a power-of-two region: size = 2^(k+3). */
static uint64_t napot_addr(uint64_t base, uint64_t size)
{
    unsigned k = 0;
    while ((1ull << (k + 3)) < size)
        k++;
    return (base >> 2) | ((1ull << k) - 1);
}

static bool pmp_match(const pmp_entry *pmp, unsigned idx, uint64_t pa)
{
    const pmp_entry *e = &pmp[idx];
    unsigned a = (e->cfg & PMP_A_MASK) >> PMP_A_SHIFT;
    uint64_t addr4 = pa >> 2;

    switch (a) {
    case A_OFF:
        return false;

    case A_TOR: {
        /* Bottom is the previous entry's pmpaddr; entry 0 starts at 0. */
        uint64_t lo = (idx == 0) ? 0 : pmp[idx - 1].pmpaddr;
        return addr4 >= lo && addr4 < e->pmpaddr;
    }

    case A_NA4:
        /* 4-byte region. E906 does not implement NA4 (treated as OFF). */
        return addr4 == e->pmpaddr;

    case A_NAPOT: {
        /*
         * k trailing ones in pmpaddr encode a 2^(k+3)-byte region.
         * Compare the address with the low k+1 bits masked off.
         */
        unsigned k = trailing_ones(e->pmpaddr);
        uint64_t mask = (k >= 63) ? ~0ull : ((1ull << (k + 1)) - 1);
        return (addr4 & ~mask) == (e->pmpaddr & ~mask);
    }

    default:
        return false;
    }
}

static bool pmp_check(const pmp_entry *pmp, unsigned nr, uint64_t pa,
                      int access, int prv, const char **why)
{
    int hit = -1;

    /* Lowest-numbered matching entry has priority. */
    for (unsigned i = 0; i < nr; i++) {
        if (pmp_match(pmp, i, pa)) {
            hit = (int)i;
            break;
        }
    }

    if (hit < 0) {
        if (prv == PRV_M) {
            *why = "no match -> M allowed";
            return true;
        }
        *why = "no match -> S/U denied";
        return false;
    }

    const pmp_entry *e = &pmp[hit];
    bool locked = (e->cfg & PMP_L) != 0;

    /* Unlocked entries are ignored by M-mode. Locked ones are not. */
    if (prv == PRV_M && !locked) {
        *why = "match -> M bypasses unlocked entry";
        return true;
    }

    unsigned need = (access == ACC_LOAD)  ? PMP_R
                  : (access == ACC_STORE) ? PMP_W
                                          : PMP_X;
    bool ok = (e->cfg & need) != 0;
    *why = ok ? "match -> permission granted" : "match -> permission denied";
    return ok;
}

static const char *acc_name(int a)
{
    return a == ACC_LOAD ? "load" : a == ACC_STORE ? "store" : "fetch";
}

static const char *prv_name(int p)
{
    return p == PRV_M ? "M" : p == PRV_S ? "S" : "U";
}

static void test(const pmp_entry *pmp, unsigned nr, uint64_t pa,
                 int access, int prv)
{
    const char *why;
    bool ok = pmp_check(pmp, nr, pa, access, prv, &why);
    printf("%-10s %-5s @0x%08llx : %-4s  (%s)\n",
           acc_name(access), prv_name(prv),
           (unsigned long long)pa, ok ? "ALLOW" : "DENY", why);
}

int main(void)
{
    /* 8 entries, like E906. */
    pmp_entry pmp[8] = {0};

    /* 0: 64 KiB at 0x8000_0000, RWX, unlocked */
    pmp[0].pmpaddr = napot_addr(0x80000000ull, 64 * 1024);
    pmp[0].cfg = PMP_R | PMP_W | PMP_X | (A_NAPOT << PMP_A_SHIFT);

    /* 1: 4 KiB at 0x8001_0000, RW, locked (applies to M-mode too) */
    pmp[1].pmpaddr = napot_addr(0x80010000ull, 4 * 1024);
    pmp[1].cfg = PMP_R | PMP_W | (A_NAPOT << PMP_A_SHIFT) | PMP_L;

    /* 2: OFF, but its pmpaddr is the TOR bottom for entry 3. */
    pmp[2].pmpaddr = 0x80020000ull >> 2;
    pmp[2].cfg = (A_OFF << PMP_A_SHIFT);

    /* 3: TOR [0x8002_0000, 0x8003_0000), read-only */
    pmp[3].pmpaddr = 0x80030000ull >> 2;
    pmp[3].cfg = PMP_R | (A_TOR << PMP_A_SHIFT);

    puts("== PMP check model ==");
    test(pmp, 8, 0x80000010, ACC_LOAD,  PRV_S);
    test(pmp, 8, 0x80000010, ACC_FETCH, PRV_M);
    test(pmp, 8, 0x80010010, ACC_STORE, PRV_S);
    test(pmp, 8, 0x80010010, ACC_FETCH, PRV_S);
    test(pmp, 8, 0x80010010, ACC_FETCH, PRV_M);
    test(pmp, 8, 0x80020010, ACC_LOAD,  PRV_S);
    test(pmp, 8, 0x80020010, ACC_STORE, PRV_S);
    test(pmp, 8, 0x90000000, ACC_LOAD,  PRV_S);
    test(pmp, 8, 0x90000000, ACC_LOAD,  PRV_M);

    return 0;
}
