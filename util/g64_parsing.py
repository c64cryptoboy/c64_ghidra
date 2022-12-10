# .g64 file parsing
#
# g64 format details: http://www.unusedino.de/ec64/technical/formats/g64.html
# 
# g64/GCR parsing borrows heavily from Michael Steil's code from here:
#     https://github.com/mist64/visualize_1541/blob/master/visualize_1541_blocks.py
# hex dump adapted from
#     https://www.geoffreybrown.com/blog/a-hexdump-program-in-python/
#
# TODO:
# - bug: data_checksum and data_checksum_expected don't match (yet...)
#

verbose = False

class Sector:
    ''' GCR-decoded sector header and data block data'''
    def __init__(self):
        # header
        self.header_checksum = None
        self.header_checksum_expected = None
        self.header_sector_num = None
        self.header_sector_num_expected = None
        self.header_track_num = None
        self.header_id2 = None
        self.header_id1 = None
        # data
        self.data = bytearray()
        self.data_checksum = None
        self.data_checksum_expected = None

    def clone(self):
        result = Sector()
        result.header_checksum = self.header_checksum
        result.header_checksum_expected = self.header_checksum_expected
        result.header_sector_num = self.header_sector_num
        result.header_sector_num_expected = self.header_sector_num_expected
        result.header_track_num = self.header_track_num
        result.header_id2 = self.header_id2
        result.header_id1 = self.header_id1
        result.data = self.data[:]
        result.data_checksum = self.data_checksum
        result.data_checksum_expected = self.data_checksum_expected
        return result

    def update_header_checksum_expected(self):
        self.header_checksum_expected = self.header_sector_num ^ self.header_track_num \
            ^ self.header_id2 ^ self.header_id1
        return self.header_checksum_expected

    def update_data_checksum_expected(self):
        self.data_checksum_expected = 0
        for val in self.data:
            self.data_checksum_expected ^= val
        return self.data_checksum_expected

    def print_sector_hexdump(self):
        note = ''
        if self.header_sector_num != self.header_sector_num_expected:
            note = ' (header lies, says sector is %d)' % self.header_sector_num
        print("\nTrack %d Sector %d%s" % (self.header_track_num, self.header_sector_num_expected, note))
        for n in range(0,16):
            b = self.data[n*16:(n+1)*16]
            s1 = " ".join([f"{i:02x}" for i in b])
            s1 = s1[0:23] + " " + s1[23:]
            s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])
            print(f"{n * 16:08x}  {s1:<{48}}  |{s2}|")

    def write_sector_data_to_file(self, file_name):
        with open(file_name, 'wb') as bf:
            bf.write(self.data)


gcr_to_dec = {
    0b01010:0x0, 0b01011:0x1, 0b10010:0x2, 0b10011:0x3, 0b01110:0x4, 0b01111:0x5, 0b10110:0x6, 0b10111:0x7,
    0b01001:0x8, 0b11001:0x9, 0b11010:0xa, 0b11011:0xb, 0b01101:0xc, 0b11101:0xd, 0b11110:0xe, 0b10101:0xf
    }

# from bytes, get 8 bits starting from the bit offset
def get_8_bits(data, offset):
    byte_offset = offset // 8
    bit_offset = offset % 8
    byte = data[byte_offset]
    next_byte = data[byte_offset + 1]
    byte_part = (byte & (((1 << (8 - bit_offset)) - 1))) << bit_offset
    byte_part_2 = next_byte >> (8 - bit_offset)
    return byte_part | byte_part_2


# from bytes, get 5 bits starting from the bit offset
def get_5_bits(data, offset):
    return get_8_bits(data, offset) >> 3


def de_gcr(five_bits):
    if not five_bits in gcr_to_dec:
        return -1
    return gcr_to_dec[five_bits]


def de_gcr_byte(data, offset):
    hi = de_gcr(get_5_bits(data, offset))
    lo = de_gcr(get_5_bits(data, offset + 5))
    if hi == -1 or lo == -1:
        return -1
    return  hi << 4 | lo


def speed_for_track(track_num):
    if track_num < 18:
        return 3
    if track_num < 25:
        return 2
    if track_num < 31:
        return 1
    return 0


def sectors_for_track(track_num):
    return [17, 18, 19, 21][speed_for_track(track_num)]


def parseG64(file):
    tracks = [[]]  # will hold tracks with their sector instances, [] at 0 for 1-indexing

    data = bytearray(open(file, 'rb').read())

    signature = data[:8]
    version = data[8]
    number_of_tracks = data[9]
    tracksize = data[10] | data[11] << 8

    for track_index in range(0, number_of_tracks):
        track_num = track_index // 2 + 1
        sector_num = -1
        ti4 = track_index * 4

        offset = data[12 + ti4] | data[12 + ti4 + 1] << 8 | data[12 + ti4 + 2] << 16 | data[12 + ti4 + 3] << 24
        speed = data[0x15c + ti4] | data[0x15c + ti4 + 1] << 8 | data[0x15c + ti4 + 2] << 16 | data[0x15c + ti4 + 3] << 24
        if not offset:
            continue

        track = []
        len = data[offset] | data[offset + 1] << 8

        sectorlen = len * 8

        print("track {}, offset {}, size {}, speed {}".format(track_num, offset, len, speed))

        is_sync = is_header =False
        last_sync = 0
        before_first_sync = True

        track_data = data[offset + 2:]

        i = header_sector_num = -1
        while i < len:
            i += 1
            byte = track_data[i]

            # Parse out sector headers;  Example from g64 spec:
            # 1. Header sync       FF FF FF FF FF (40 'on' bits, not GCR)
            # 2. Header info       52 54 B5 29 4B 7A 5E 95 55 55 (10 GCR bytes)
            # 3. Header gap        55 55 55 55 55 55 55 55 55 (9 bytes, never read)
            # 4. Data sync         FF FF FF FF FF (40 'on' bits, not GCR)
            # 5. Data block        55...4A (325 GCR bytes)
            # 6. Inter-sector gap  55 55 55 55...55 55 (4 to 12 bytes, never read)

            # Processing G64 as a stream of bits
            for j in range(0, 8):
                next_bit = ((byte << j) & 0x80) >> 7  # each bit, from b7 to b0
                data2 = track_data[i:]
                if get_5_bits(data2, j) == 0x1F and get_5_bits(data2, j + 5) == 0x1F:
                    is_sync = True

                if is_sync and next_bit == 0:
                    is_sync = False

                    was_short_data = not before_first_sync and not is_header and i - last_sync < 320
                    if was_short_data:
                        print("Warning: Sector {}: short data: {} bytes".format(header_sector_num, i - last_sync))
                    before_first_sync = False

                    last_sync = i

                    # sector header data, from g64 spec:
                    # Byte   $00 - header block ID ($08)
                    #         01 - header block checksum (EOR of $02-$05)
                    #         02 - Sector
                    #         03 - Track
                    #         04 - Format ID byte #2
                    #         05 - Format ID byte #1
                    #      06-07 - $0F ("off" bytes)
                    header_data = track_data[i:]
                    code = de_gcr_byte(header_data, j)
                    if code == 8: # header
                        header_checksum = de_gcr_byte(header_data, j + 10)
                        header_sector_num = de_gcr_byte(header_data, j + 20)
                        header_track_num = de_gcr_byte(header_data, j + 30)
                        header_id2 = de_gcr_byte(header_data, j + 40)
                        header_id1 = de_gcr_byte(header_data, j + 50)
                        is_header = True
                        if verbose:
                            print("header", header_track_num, header_sector_num)

                        # might as well skip past 10 bytes of GCRed header and into the header gap
                        i += 10-1 # todo: could skip some header gap too
                        break

                    elif code == 7: # data
                        if is_header:
                            is_header = False
                            sector_num += 1
                            if verbose:
                                print("data t:%s, s:%d, expected sector:%d " % (track_num, header_sector_num, sector_num))

                            # sector data, from G64 spec:
                            # 325 GCR-encoded bytes = 2600 GCR-encoded bits = 520 GCR nibbles = 260 non-GCR bytes.  From doc:
                            #     Byte    $00 - data block ID ($07)
                            #          01-100 - 256 bytes data
                            #             101 - data block checksum (EOR of $01-100)
                            #         102-103 - $00 ("off" bytes, to make the sector size a multiple of 5)
                            sector_decoded = bytearray()
                            sector_end = j+10+325*8
                            for k in range(j+10, sector_end, 10): # 10 bits for a GCR byte
                                sector_decoded += bytes([de_gcr_byte(data2, k)])
                            data_checksum = de_gcr_byte(data2, sector_end)

                            a_sector = Sector()
                            a_sector.header_sector_num = header_sector_num
                            a_sector.header_track_num = header_track_num
                            a_sector.header_id2 = header_id2
                            a_sector.header_id1 = header_id1
                            a_sector.update_header_checksum_expected()
                            a_sector.header_checksum = header_checksum
                            a_sector.header_sector_num_expected = sector_num
                            a_sector.data = sector_decoded
                            a_sector.update_data_checksum_expected()
                            a_sector.data_checksum = data_checksum

                            track.append(a_sector)

                            '''
                                Detects "duplicate sectors"
                                According to https://c64preservation.com/dp.php?pg=database
                                this form of copy protection was used a few times:
                                - Epyx 1984: 9 to 5 Typing, Impossible Mission, Monty Plays Scrabble, and Puzzle Panic
                                - Synapse 1984: Encounter
                                - HES 1984: Cell Defense
                                - Epyx 1985: Chipwits
                            '''
                            if a_sector.header_sector_num != sector_num or a_sector.header_track_num != track_num:
                                print("*** Note: T%d S%d labeled in headers as T%d S%d" %
                                    (track_num, sector_num, a_sector.header_track_num, 
                                    a_sector.header_sector_num))

                            if verbose:
                                a_sector.print_sector_hexdump()

                            # might as well skip past the sector data into the inter-sector gap
                            i += 325-1 # todo: could skip some gap bytes too
                            break

                        else:
                            if was_short_data:
                                exit('Error: "short data" not handled')
                            '''    
                                # Common error: The drive wrote the sector too late, so the original SYNC and ~28
                                # GCR bytes are still intact, but aborted, followed by the newly written SYNC and
                                # the new data. We will ignore the aborted sector and assume the data after the
                                # SYNC is the correct version of the same sector.
                                # Note that this error probably also means that the next sector's header is missing
                                # (which we can recover from), and maybe even the SYNC of the next data block is
                                # missing(which we can't recover from).
                                print("Warning: No header, but short data! Assuming repeated sector {}".format(header_sector_num))
                            else:
                                header_sector_num += 1
                                if header_sector_num > sectors_for_track(track_num):
                                    header_sector_num = 0
                                print("Warning: No header! Assuming sector {}".format(header_sector_num))
                            '''
                    else:
                        print("Warning: Code {}".format(code))
                        header_checksum = de_gcr_byte(header_data, j + 10)
                        header_sector_num = de_gcr_byte(header_data, j + 20)
                        header_track_num = de_gcr_byte(header_data, j + 30)

                    if header_sector_num >= sectors_for_track(track_num):
                        print("Warning: Extra sector {}".format(header_sector_num))
        tracks.append(track)

    return tracks
