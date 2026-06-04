#include "baseline_decide.h"
#include "baseline_set.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    struct ps_baseline_set bl, den;
    ps_blset_init(&bl, "/x"); ps_blset_init(&den, "/x");
    ps_blset_add(&bl, "/var/www");
    ps_blset_add(&den, "/etc/shadow");
    assert(ps_baseline_decide(&bl, &den, "/var/www/index.html") == PS_BL_COVERED);
    assert(ps_baseline_decide(&bl, &den, "/etc/shadow") == PS_BL_ANOMALY);
    assert(ps_baseline_decide(&bl, &den, "/tmp/new") == PS_BL_NOVEL);
    /* baseline wins over denial if both match (approved beats denied) */
    ps_blset_add(&bl, "/etc/shadow");
    assert(ps_baseline_decide(&bl, &den, "/etc/shadow") == PS_BL_COVERED);

    struct ps_baseline_set dbl, dden;
    ps_blset_init(&dbl, "/x"); ps_blset_init(&dden, "/x");
    ps_blset_add(&dbl, "1.2.3.0/24");      /* approved subnet */
    ps_blset_add(&dden, "6.6.6.6");        /* denied host */
    assert(ps_baseline_decide_dest(&dbl, &dden, "1.2.3.9:443") == PS_BL_COVERED);
    assert(ps_baseline_decide_dest(&dbl, &dden, "6.6.6.6:1337") == PS_BL_ANOMALY);
    assert(ps_baseline_decide_dest(&dbl, &dden, "9.9.9.9:443") == PS_BL_NOVEL);

    printf("test_baseline_decide: OK\n");
    return 0;
}
