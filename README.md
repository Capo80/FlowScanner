# FlowScanner

Anonimized repository for the FlowScanner ASPLOS 2026 submission.

FlowScanner is a Kernel module which allows for the tracing at the basic-block level of user application.


https://github.com/user-attachments/assets/1a948f0b-4d28-44bd-bb82-72ef17bf9ec2


## Using FlowScanner

FlowScanner has been tested on Kernel 6.8.0, it is not guaranteed to work on other kernel versions.

To compile and run the code you can use the Makefile in this directory, to run FlowScanner in its default configuration you can do the following:
```
make && insmod hook.ko
```
Then you can use the python user agent to observe the traced blocks:
```
python3 user/agent_zone.py &
gcc test/other_test/vuln.c && a.out
```
By default it will only trace programs named ```a.out``` and the Spec CPU binaries. If you want to trace something else you can change the names in the mod.c file and then recompile.

## Folder Structure

The folders are stuctured as follows:
- "src" contains the source code of FlowScanner;
- "user" contains the user agents that can be used to interact with FlowScanner and some other user-level applications we used during development and testing;
- "test/data_analisys" contains the data used for the "/usr/bin" memory usage statistics;
- "test/other_test" contains some edge cases we used for FlowScanner during development;
- "test/performance_test" contains the code used to run the jit-benchmarks test;
- "test/signature_test" contains the code we used to generate and test the code-only signatures;


