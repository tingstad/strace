# strace

Zero-dependency strace implementation based on [lizrice/strace-from-scratch](https://github.com/lizrice/strace-from-scratch).

Arranged to be modifiable using different `Interceptor`s. The default simply prints system calls:

```
docker run --rm strace echo -n hi
Run [echo -n hi]
arch_prctl
set_tid_address
brk
brk
mmap(94127144218624, 4096, 0, 50, -1, 0)
mprotect
mprotect
getuid() = 0
write(1, "\"hi\"", 2) hi= 2
exit_group
```

### HTTP proxy

Another interceptor can be enabled with env variables:

```
INTER_FILE=file.zip INTER_URL=https://i.ting.st/pg2701.epub ./main unzip -l file.zip
...
lseek(3<file.zip>, 628018, SEEK_SET) = 628018
read(3<file.zip>, 140725387582132, 4)

> GET https://i.ting.st/pg2701.epub
> Range: bytes=628018-628022

< HTTP/2.0 206 Partial Content
< content-length: 5

= 4: "PK\x05\x06"
writev
 --------                     -------
writev
  1540943                     35 files
exit_group
```

Let's use *nix tools with web resources!
