#include "patch.h"

#include <log.h>
#include <ksyms.h>
#include <kallsyms.h>
#include <hook.h>
#include <accctl.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <syscall.h>
#include <module.h>
#include <predata.h>
#include <linux/string.h>

int linux_misc_symbol_init();
int linux_libs_symbol_init();

int resolve_struct();
int task_observer();
int bypass_kcfi();
int resolve_pt_regs();

void print_bootlog()
{
    const char *log = get_boot_log();
    char buf[1024];
    int off = 0;
    char c;
    for (int i = 0; (c = log[i]); i++) {
        if (c == '\n') {
            buf[off++] = c;
            buf[off] = '\0';

            printk("KP %s", buf);
            off = 0;
        } else {
            buf[off++] = log[i];
        }
    }
}

void before_panic(hook_fargs12_t *args, void *udata)
{
    printk("==== Start KernelPatch for Kernel panic ====\n");
    print_bootlog();
    printk("==== End KernelPatch for Kernel panic ====\n");
}

static void before_rest_init(hook_fargs4_t *args, void *udata)
{
    int rc = 0;
    log_boot("entering init ...\n");

    if ((rc = linux_libs_symbol_init())) goto out;
    log_boot("linux_libs_symbol_init done: %d\n", rc);

    if ((rc = linux_misc_symbol_init())) goto out;
    log_boot("linux_misc_symbol_init done: %d\n", rc);

    if ((rc = bypass_kcfi())) goto out;
    log_boot("bypass_kcfi done: %d\n", rc);

    if ((rc = syscall_init())) goto out;
    log_boot("syscall_init done: %d\n", rc);

    if ((rc = resolve_struct())) goto out;
    log_boot("resolve_struct done: %d\n", rc);

    if ((rc = selinux_hook_install())) goto out;
    log_boot("selinux_hook_install done: %d\n", rc);

    if ((rc = task_observer())) goto out;
    log_boot("task_observer done: %d\n", rc);

    if ((rc = module_init())) goto out;
    log_boot("module_init done: %d\n", rc);

    rc = supercall_install();
    log_boot("supercall_install done: %d\n", rc);

    rc = resolve_pt_regs();
    log_boot("resolve_pt_regs done: %d\n", rc);

#ifdef ANDROID
    rc = su_compat_init();
    log_boot("su_compat_init done: %d\n", rc);

    rc = kpuserd_init();
    log_boot("kpuserd_init done: %d\n", rc);
#endif

out:
    return;
}

static int pre_kernel_init(const patch_extra_item_t *extra, const char *args, const void *data, void *udata)
{
    const char *event = (const char *)udata;
    if (extra->type == EXTRA_TYPE_KPM) {
        if (!strcmp(EXTRA_EVENT_PRE_KERNEL_INIT, extra->event) || !extra->event[0]) {
            int rc = load_module(data, extra->con_size, args, event, 0);
            log_boot("%s loading extra kpm return: %d\n", event, rc);
        }
    }
    return 0;
}

static void before_kernel_init(hook_fargs4_t *args, void *udata)
{
    log_boot("event: %s\n", EXTRA_EVENT_PRE_KERNEL_INIT);
    on_each_extra_item(pre_kernel_init, 0);
}

static void after_kernel_init(hook_fargs4_t *args, void *udata)
{
    log_boot("event: %s\n", EXTRA_EVENT_POST_KERNEL_INIT);
}
static void replace_string(char *original, u32 orig_len,const char *pattern, const char *replacement) {
    int pat_len = strlen(pattern);
    int rep_len = strlen(replacement);

    int i, j, k = 0;

    for (i = 0; i < orig_len; i++) {
        // 如果找到了与pattern匹配的子字符串
        if (strncmp(original + i, pattern, pat_len) == 0) {
            // 复制replacement字符串到original中
            for (j = 0; j < rep_len; j++) {
                original[i + j] = replacement[j];
            }
            // 移动剩余的字符
            for (k = i + rep_len; k < orig_len; k++) {
                original[k] = original[k + pat_len - rep_len];
            }
            // 更新i，以便跳过已匹配的部分
            i += rep_len - 1;
        }
    }
}
static void before_xbc_init(hook_fargs4_t *args, void *udata){
    char *data = (char*)args->arg0;
    size_t size =  strlen(data);
	replace_string(data,size, "orange", "green");
	replace_string(data,size, "unlocked", "locked");    
}
int patch()
{
    hook_err_t ret = 0;

    unsigned long panic_addr = get_preset_patch_sym()->panic;
    if (panic_addr) {
        hook_err_t rc = hook_wrap12((void *)panic_addr, before_panic, 0, 0);
        log_boot("hook panic rc: %d\n", rc);
        ret |= rc;
    }

    // rest_init or cgroup_init
    unsigned long init_addr = get_preset_patch_sym()->rest_init;
    if (!init_addr) init_addr = get_preset_patch_sym()->cgroup_init;
    if (init_addr) {
        hook_err_t rc = hook_wrap4((void *)init_addr, before_rest_init, 0, (void *)init_addr);
        log_boot("hook rest_init rc: %d\n", rc);
        ret |= rc;
    }

    // kernel_init
    unsigned long kernel_init_addr = get_preset_patch_sym()->kernel_init;
    if (kernel_init_addr) {
        hook_err_t rc = hook_wrap4((void *)kernel_init_addr, before_kernel_init, after_kernel_init, 0);
        log_boot("hook kernel_init rc: %d\n", rc);
        ret |= rc;
    }
    // xbc_init
    unsigned long xbc_init_addr = get_preset_patch_sym()->xbc_init;
    if (xbc_init_addr) {
        hook_err_t rc = hook_wrap4((void *)xbc_init_addr, before_xbc_init, 0, 0);
        log_boot("hook xbc_init rc: %d\n", rc);
        ret |= rc;
    }
    return ret;
}
