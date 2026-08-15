#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>

/* Auto-generated headers via xxd */
#include "include/android12-5.10-lkmloader.h"
#include "include/android13-5.10-lkmloader.h"
#include "include/android13-5.15-lkmloader.h"
#include "include/android14-5.15-lkmloader.h"
#include "include/android14-6.1-lkmloader.h"
#include "include/android15-6.6-lkmloader.h"
#include "include/android16-6.12-lkmloader.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

typedef struct {
    const char *kmi;
    const unsigned char *data;
    unsigned int len;
} kmi_asset_t;

/* Map KMI strings to their respective xxd-generated arrays */
kmi_asset_t supported_kmis[] = {
    {"android12-5.10", android12_5_10_lkmloader_ko, sizeof(android12_5_10_lkmloader_ko)},
    {"android13-5.10", android13_5_10_lkmloader_ko, sizeof(android13_5_10_lkmloader_ko)},
    {"android13-5.15", android13_5_15_lkmloader_ko, sizeof(android13_5_15_lkmloader_ko)},
    {"android14-5.15", android14_5_15_lkmloader_ko, sizeof(android14_5_15_lkmloader_ko)},
    {"android14-6.1",  android14_6_1_lkmloader_ko,  sizeof(android14_6_1_lkmloader_ko)},
    {"android15-6.6",  android15_6_6_lkmloader_ko,  sizeof(android15_6_6_lkmloader_ko)},
    {"android16-6.12", android16_6_12_lkmloader_ko, sizeof(android16_6_12_lkmloader_ko)},
};

/* 
 * Fallback to read vermagic from a random kernel module 
 * in /vendor/lib/modules if uname() doesn't contain the expected format.
 */
static int get_kmi_from_modinfo(char *out_kmi, size_t max_len) {
    DIR *dir = opendir("/vendor/lib/modules");
    if (!dir) return -1;

    struct dirent *entry;
    char mod_path[PATH_MAX] = {0};

    /* Find the first .ko file in the directory */
    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        if (len > 3 && strcmp(entry->d_name + len - 3, ".ko") == 0) {
            snprintf(mod_path, sizeof(mod_path), "/vendor/lib/modules/%s", entry->d_name);
            break;
        }
    }
    closedir(dir);

    if (mod_path[0] == '\0') return -1;

    char cmd[PATH_MAX + 32];
    snprintf(cmd, sizeof(cmd), "modinfo %s 2>/dev/null", mod_path);
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "vermagic:", 9) == 0) {
            strncpy(out_kmi, line, max_len - 1);
            found = 1;
            break;
        }
    }
    pclose(fp);
    return found ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usages: %s MODULE\n", argv[0]);
        fprintf(stderr, "  Load the module named MODULE passing options if given.\n");
        return 1;
    }

    char abs_path[PATH_MAX];
    if (!realpath(argv[1], abs_path)) {
        perror("Resolve module path failed");
        return 1;
    }

    /* Grab release string from uname */
    struct utsname uts;
    if (uname(&uts) != 0) {
        perror("Uname failed");
        return 1;
    }

    char signature_string[512];
    strncpy(signature_string, uts.release, sizeof(signature_string));
    kmi_asset_t *target_asset = NULL;

    /* 
     * Evaluation loop: Try with uname first, 
     * if it fails, fallback to modinfo and try again.
     */
    for (int attempt = 0; attempt < 2; attempt++) {
        for (int i = 0; i < ARRAY_SIZE(supported_kmis); i++) {
            char android_ver[32], kernel_ver[32];

            /* Parse strings like "android12" and "5.10" */
            sscanf(supported_kmis[i].kmi, "%[^-]-%s", android_ver, kernel_ver);
            if (strstr(signature_string, android_ver) && strstr(signature_string, kernel_ver)) {
                target_asset = &supported_kmis[i];
                break;
            }
        }

        if (target_asset) break;

        /* If uname failed, load the vermagic string for the second attempt */
        if (attempt == 0) {
            if (get_kmi_from_modinfo(signature_string, sizeof(signature_string)) != 0) {
                break; 
            }
        }
    }

    if (!target_asset) {
        fprintf(stderr, "Unsupported KMI!! (release/vermagic: %s)\n", signature_string);
        return 1;
    }

    char params[PATH_MAX + 32];
    snprintf(params, sizeof(params), "module_path=%s", abs_path);

    long ret = syscall(SYS_init_module, target_asset->data, target_asset->len, params);
    if (ret == 0) {
        printf("Loaded kernel module: %s\n", abs_path);
        return 0;
    } else {
        perror("init_module failed");
        return 1;
    }
}
