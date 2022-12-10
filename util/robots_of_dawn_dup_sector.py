from g64_parsing import parseG64, Sector

tracks = parseG64('util/robots_of_dawn.g64')

t21s3 = tracks[21][3]
t21s3.print_sector_hexdump()

t21s18 = tracks[21][18]
t21s18.print_sector_hexdump()

combined = t21s3.clone()
combined.data = bytearray()
for i in range(0, 256):
    combined.data += bytes([t21s3.data[i] ^ t21s18.data[i]])
combined.print_sector_hexdump()

combined.write_sector_data_to_file("util/combined.bin")

print("\nDone")


"""
output from run:

track 1, offset 684, size 7692, speed 3
track 2, offset 8614, size 7692, speed 3
track 3, offset 16544, size 7692, speed 3
track 4, offset 24474, size 7692, speed 3
track 5, offset 32404, size 7692, speed 3
track 6, offset 40334, size 7692, speed 3
track 7, offset 48264, size 7692, speed 3
track 8, offset 56194, size 7692, speed 3
track 9, offset 64124, size 7692, speed 3
track 10, offset 72054, size 7692, speed 3
track 11, offset 79984, size 7692, speed 3
track 12, offset 87914, size 7692, speed 3
track 13, offset 95844, size 7692, speed 3
track 14, offset 103774, size 7692, speed 3
track 15, offset 111704, size 7692, speed 3
track 16, offset 119634, size 7692, speed 3
track 17, offset 127564, size 7692, speed 3
track 18, offset 135494, size 6961, speed 2
track 19, offset 143424, size 6960, speed 2
track 20, offset 151354, size 6964, speed 2
track 21, offset 159284, size 6961, speed 2
*** Note: T21 S18 labeled in headers as T21 S3
track 22, offset 167214, size 6960, speed 2
track 23, offset 175144, size 6962, speed 2
track 24, offset 183074, size 6962, speed 2
track 25, offset 191004, size 6593, speed 1
track 26, offset 198934, size 6593, speed 1
track 27, offset 206864, size 6597, speed 1
track 28, offset 214794, size 6591, speed 1
track 29, offset 222724, size 6593, speed 1
track 30, offset 230654, size 6593, speed 1
track 31, offset 238584, size 6241, speed 0
track 32, offset 246514, size 6241, speed 0
track 33, offset 254444, size 6240, speed 0
track 34, offset 262374, size 6242, speed 0
track 35, offset 270304, size 6239, speed 0
track 36, offset 278234, size 7108, speed 2
Warning: Code 15

Track 21 Sector 3
00000000  a0 00 20 90 f0 a0 00 a0  00 a0 00 20 b0 f0 a0 00  |.. ........ ....|
00000010  a0 10 a0 00 20 b0 f0 a0  00 20 d0 f0 a0 00 80 10  |.... .... ......|
00000020  a0 50 a0 f0 80 10 a0 50  a0 00 80 10 a0 d0 20 e0  |.P.....P...... .|
00000030  00 20 e0 00 a0 00 80 10  a0 50 a0 00 80 10 a0 60  |. .......P.....`|
00000040  a0 00 80 10 a0 d0 20 e0  00 20 d0 00 a0 10 d0 20  |...... .. ..... |
00000050  d0 80 10 d0 a0 10 d0 20  e0 80 10 d0 a0 00 d0 00  |....... ........|
00000060  00 80 00 d0 a0 00 d0 20  f0 80 00 d0 a0 00 80 20  |....... ....... |
00000070  d0 80 20 d0 80 20 d0 80  20 d0 80 20 d0 a0 50 80  |.. .. .. .. ..P.|
00000080  10 d0 a0 00 a0 00 a0 00  20 b0 f0 a0 00 a0 20 a0  |........ ..... .|
00000090  00 20 b0 f0 a0 00 20 d0  f0 20 e0 00 a0 00 80 10  |. .... .. ......|
000000a0  a0 10 a0 f0 80 10 a0 20  a0 00 80 10 a0 e0 20 e0  |....... ...... .|
000000b0  00 20 d0 00 a0 00 a0 00  a0 00 20 b0 f0 a0 00 a0  |. ........ .....|
000000c0  10 a0 00 20 b0 f0 a0 00  20 d0 f0 a0 00 d0 00 00  |... .... .......|
000000d0  80 00 d0 a0 00 d0 00 00  80 00 d0 40 00 00 40 a0  |...........@..@.|
000000e0  30 80 00 60 50 60 70 40  a0 30 80 00 60 60 80 10  |0..`P`p@.0..``..|
000000f0  80 10 80 10 a0 00 a0 00  a0 10 90 10 c0 d0 00 e0  |................|

Track 21 Sector 18 (header lies, says sector is 3)
00000000  09 00 00 00 0f 00 01 09  02 02 08 00 0a 0f 09 08  |................|
00000010  02 04 00 0a 00 0d 0f 09  00 00 05 0f 09 00 05 00  |................|
00000020  02 08 09 0f 05 04 00 0b  09 00 05 02 09 08 00 0e  |................|
00000030  09 00 06 09 09 00 05 00  02 0c 09 00 05 04 00 08  |................|
00000040  09 00 05 02 09 04 00 0e  09 00 0e 09 0d 01 00 09  |................|
00000050  0f 0d 01 00 0d 06 00 09  0f 0d 06 00 0d 02 0d 09  |................|
00000060  03 0d 02 0d 0d 00 0d 09  0c 0d 00 0d 09 00 0d 00  |................|
00000070  00 0d 01 00 0d 02 00 0d  03 00 0d 04 00 09 06 0d  |................|
00000080  08 00 00 01 09 02 02 08  00 0a 0f 09 07 02 03 00  |................|
00000090  0a 00 0d 0f 09 00 00 05  0f 00 06 09 09 00 05 00  |................|
000000a0  02 00 09 00 05 04 00 0f  09 00 05 02 09 00 00 0e  |................|
000000b0  09 00 0e 09 00 01 09 02  02 08 00 0a 0f 09 07 02  |................|
000000c0  0c 00 0a 00 0d 0f 09 00  00 05 0f 0d 02 0d 09 03  |................|
000000d0  0d 02 0d 0d 00 0d 09 03  0d 00 0d 0c 00 0c 08 09  |................|
000000e0  06 05 01 08 08 00 08 08  09 04 05 01 08 00 06 01  |................|
000000f0  05 03 04 05 02 00 00 00  01 00 01 02 08 00 02 06  |................|

Track 21 Sector 3
00000000  a9 00 20 90 ff a0 01 a9  02 a2 08 20 ba ff a9 08  |.. ........ ....|
00000010  a2 14 a0 0a 20 bd ff a9  00 20 d5 ff a9 00 85 10  |.... .... ......|
00000020  a2 58 a9 ff 85 14 a0 5b  a9 00 85 12 a9 d8 20 ee  |.X.....[...... .|
00000030  09 20 e6 09 a9 00 85 10  a2 5c a9 00 85 14 a0 68  |. .......\.....h|
00000040  a9 00 85 12 a9 d4 20 ee  09 20 de 09 ad 11 d0 29  |...... .. .....)|
00000050  df 8d 11 d0 ad 16 d0 29  ef 8d 16 d0 ad 02 dd 09  |.......)........|
00000060  03 8d 02 dd ad 00 dd 29  fc 8d 00 dd a9 00 8d 20  |.......)....... |
00000070  d0 8d 21 d0 8d 22 d0 8d  23 d0 8d 24 d0 a9 56 8d  |..!.."..#..$..V.|
00000080  18 d0 a0 01 a9 02 a2 08  20 ba ff a9 07 a2 23 a0  |........ .....#.|
00000090  0a 20 bd ff a9 00 20 d5  ff 20 e6 09 a9 00 85 10  |. .... .. ......|
000000a0  a2 10 a9 f0 85 14 a0 2f  a9 00 85 12 a9 e0 20 ee  |......./...... .|
000000b0  09 20 de 09 a0 01 a9 02  a2 08 20 ba ff a9 07 a2  |. ........ .....|
000000c0  1c a0 0a 20 bd ff a9 00  20 d5 ff ad 02 dd 09 03  |... .... .......|
000000d0  8d 02 dd ad 00 dd 09 03  8d 00 dd 4c 00 0c 48 a9  |...........L..H.|
000000e0  36 85 01 68 58 60 78 48  a9 34 85 01 68 60 86 11  |6..hX`xH.4..h`..|
000000f0  85 13 84 15 a2 00 a0 00  a1 10 91 12 c8 d0 02 e6  |................|

Done

"""

