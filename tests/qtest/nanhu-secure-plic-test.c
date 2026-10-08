/*
 * Nanhu secure PLIC ID-indexed SEC_SRC regression tests.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "libqtest.h"

#define PLIC_BASE       0x3c000000
#define SEC_SRC         (PLIC_BASE + 0x4000)
#define SEC_CTRL        (PLIC_BASE + 0x4100)
#define WORLD_STATE     (PLIC_BASE + 0x4200)
#define SEC_STATUS      (PLIC_BASE + 0x4e00)
#define ENABLE(ctx)     (PLIC_BASE + 0x2000 + 0x80 * (ctx))
#define CLAIM(ctx)      (PLIC_BASE + 0x200004 + 0x1000 * (ctx))
#define TRACK(ctx)      (PLIC_BASE + 0x4600 + 8 * (ctx))
#define COMPLETE_SECURE (1U << 31)
#define M_CONTEXT      0
#define S_CONTEXT      1

static QTestState *plic_start(void)
{
    return qtest_init("-machine xiangshan-nanhuv5 -smp 1 -m 512M");
}

static void bitmap_set(QTestState *qts, uint64_t base, unsigned int irq)
{
    uint64_t addr = base + 4 * (irq / 32);

    qtest_writel(qts, addr, qtest_readl(qts, addr) | (1U << (irq % 32)));
}

static void enable_irq(QTestState *qts, unsigned int irq)
{
    qtest_writel(qts, PLIC_BASE + 4 * irq, 1);
    bitmap_set(qts, ENABLE(M_CONTEXT), irq);
    bitmap_set(qts, ENABLE(S_CONTEXT), irq);
}

static void raise_irq(QTestState *qts, unsigned int irq)
{
    /* The Nanhu board creates its PLIC as the first unattached device. */
    qtest_set_irq_in(qts, "/machine/unattached/device[0]", NULL, irq, 1);
    qtest_set_irq_in(qts, "/machine/unattached/device[0]", NULL, irq, 0);
}

static void check_irq(QTestState *qts, unsigned int irq, bool secure,
                      unsigned int world)
{
    unsigned int ctx = secure == world ? S_CONTEXT : M_CONTEXT;
    uint32_t track = (irq << 2) | (secure ? 2 : 0) | 1;
    uint32_t complete = irq | (secure ? COMPLETE_SECURE : 0);

    raise_irq(qts, irq);
    g_assert_cmphex(qtest_readl(qts, CLAIM(ctx ^ 1)), ==, 0);
    g_assert_cmphex(qtest_readl(qts, CLAIM(ctx)), ==, irq);
    g_assert_cmphex(qtest_readl(qts, TRACK(ctx)), ==, track);
    g_assert_cmphex(qtest_readl(qts, CLAIM(ctx)), ==, 0);

    /* A mismatched complete must not release the in-service source. */
    qtest_writel(qts, CLAIM(ctx), complete ^ COMPLETE_SECURE);
    g_assert_cmphex(qtest_readl(qts, TRACK(ctx)), ==, track);
    g_assert_cmphex(qtest_readl(qts, SEC_STATUS), ==, 1);
    qtest_writel(qts, SEC_STATUS, 1);

    qtest_writel(qts, CLAIM(ctx), complete);
    g_assert_cmphex(qtest_readl(qts, TRACK(ctx)), ==, track & ~1U);
    g_assert_cmphex(qtest_readl(qts, SEC_STATUS), ==, 0);

    qtest_writel(qts, CLAIM(ctx), complete);
    g_assert_cmphex(qtest_readl(qts, SEC_STATUS), ==, 1);
    qtest_writel(qts, SEC_STATUS, 1);
}

static void test_source_id(const void *opaque)
{
    unsigned int irq = GPOINTER_TO_UINT(opaque);
    QTestState *qts = plic_start();
    unsigned int first = irq > 1 ? irq - 1 : irq;
    unsigned int last = MIN(irq + 1, 255);

    g_assert_cmphex(qtest_readl(qts, WORLD_STATE), ==, 1);
    bitmap_set(qts, SEC_SRC, irq);
    g_assert_cmphex(qtest_readl(qts, SEC_SRC + 4 * (irq / 32)),
                    ==, 1U << (irq % 32));
    for (unsigned int id = first; id <= last; id++) {
        enable_irq(qts, id);
    }
    qtest_writel(qts, SEC_CTRL, 3);
    /* Lock freezes both the bitmap and the routing enable. */
    qtest_writel(qts, SEC_SRC + 4 * (irq / 32), 0);
    qtest_writel(qts, SEC_CTRL, 0);
    g_assert_cmphex(qtest_readl(qts, SEC_CTRL), ==, 3);
    g_assert_cmphex(qtest_readl(qts, SEC_SRC + 4 * (irq / 32)),
                    ==, 1U << (irq % 32));

    for (unsigned int world = 0; world <= 1; world++) {
        qtest_writel(qts, WORLD_STATE, world);
        for (unsigned int id = first; id <= last; id++) {
            check_irq(qts, id, id == irq, world);
        }
    }
    qtest_quit(qts);
}

static void test_reserved_bit(void)
{
    QTestState *qts = plic_start();

    qtest_writel(qts, SEC_SRC, UINT32_MAX);
    g_assert_cmphex(qtest_readl(qts, SEC_SRC), ==, UINT32_MAX - 1);
    qtest_writel(qts, SEC_SRC, 1);
    g_assert_cmphex(qtest_readl(qts, SEC_SRC), ==, 0);
    qtest_quit(qts);
}

static void test_secure_busy(void)
{
    QTestState *qts = plic_start();

    bitmap_set(qts, SEC_SRC, 41);
    enable_irq(qts, 40);
    enable_irq(qts, 41);
    qtest_writel(qts, SEC_CTRL, 3);
    raise_irq(qts, 41);
    g_assert_cmphex(qtest_readl(qts, CLAIM(S_CONTEXT)), ==, 41);
    g_assert_cmphex(qtest_readl(qts, TRACK(S_CONTEXT)), ==, (41 << 2) | 3);

    raise_irq(qts, 40);
    g_assert_cmphex(qtest_readl(qts, CLAIM(M_CONTEXT)), ==, 0);
    g_assert_cmphex(qtest_readl(qts, CLAIM(S_CONTEXT)), ==, 0);
    qtest_writel(qts, CLAIM(S_CONTEXT), COMPLETE_SECURE | 41);
    g_assert_cmphex(qtest_readl(qts, CLAIM(M_CONTEXT)), ==, 40);
    g_assert_cmphex(qtest_readl(qts, TRACK(M_CONTEXT)), ==, (40 << 2) | 1);
    qtest_writel(qts, CLAIM(M_CONTEXT), 40);
    g_assert_cmphex(qtest_readl(qts, SEC_STATUS), ==, 0);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    static const unsigned int ids[] = { 1, 31, 32, 41, 255 };

    g_test_init(&argc, &argv, NULL);
    for (unsigned int i = 0; i < G_N_ELEMENTS(ids); i++) {
        g_autofree char *name =
            g_strdup_printf("/nanhu/plic/source-%u", ids[i]);

        qtest_add_data_func(name, GUINT_TO_POINTER(ids[i]), test_source_id);
    }
    qtest_add_func("/nanhu/plic/reserved-bit", test_reserved_bit);
    qtest_add_func("/nanhu/plic/secure-busy", test_secure_busy);
    return g_test_run();
}
