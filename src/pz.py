ENCODING: str = "utf-8"


def byte_to_int(
    byte: bytes,
) -> int | list[int]:
    assert len(byte) > 0
    if len(byte) == 1:
        return int(byte.hex(), base=16)
    if len(byte) > 1:
        return [int(byte_.hex(), base=16) for byte_ in byte]


def int_to_byte(
    integer: int | list[int],
) -> bytes:
    if isinstance(integer, int):
        return bytes([integer])
    if isinstance(integer, list):
        return bytes(integer)


def string_to_bytes(
    string: str,
) -> bytes:
    return bytes(string, encoding=ENCODING)


def bytes_to_string(
    bytes_: bytes,
) -> str:
    assert bytes_.isascii()
    return bytes_.decode(encoding=ENCODING)


DICT_BYTE_START: int = byte_to_int(b"!")
MAX_BYTE_RANGE: int = 255 - DICT_BYTE_START

from dataclasses import dataclass


@dataclass
class KeyMap:
    key: bytes | None = None
    charpair: bytes | None = None

    @property
    def is_empty(self):
        return self.key is None


@dataclass
class OrderedKeyMap:
    order: list[KeyMap] | None = None

    @property
    def is_empty(self):
        return self.order is None

    @property
    def keymap_size(self) -> int:
        """3 times length of keymaps."""
        if self.is_empty:
            return 0
        return len(self.order) * 3

    def add_keymap(self, keymap: KeyMap) -> None:
        assert not keymap.is_empty
        if self.is_empty:
            self.order = []
        self.order.append(keymap)
        return


@dataclass
class SizeLog:
    size_chunk: int
    size_keymap: int

    @property
    def size_total(self) -> int:
        return self.size_chunk + self.size_keymap


def chunk_pz_once(chunk: bytes) -> tuple[bytes, KeyMap]:
    """Compress a chunk of string for one iteration.
    1. Find the most frequent char-pair, e.g. xx;
    2. Find a not-used char as key, e.g. A;
    3. Create a mapping A -> xx.

    Example:
    Sentence: How about your cow? -> Counter(ow: 2, ou:2, ...);
    A in Sentence? -> No -> Mapping: A -> ow.

    Return:
        tuple: (chunk_compressed: str, KeyMap(key: str, charpair: str), could be empty)
    """

    n_chars: int = len(chunk)
    counter: dict[bytes, int] = dict()
    max_freq: tuple[int, bytes] = (0, b"")
    chars_unique: set[bytes] = set()
    for iloc_cpair in range(n_chars - 1):
        # str: 1234567  n_chars=7
        # idx: 0123456
        #           ^   last possible iloc
        cpair: bytes = chunk[iloc_cpair : iloc_cpair + 2]
        chars_unique.add(chunk[iloc_cpair : iloc_cpair + 1])
        if cpair not in counter:
            counter[cpair] = 1
        else:
            counter[cpair] += 1
        if counter[cpair] > max_freq[0]:
            max_freq = (counter[cpair], cpair)
    if max_freq[0] <= 2:
        keymap = KeyMap()
        chuck_replaced: bytes = chunk
    else:
        for byte_key in range(DICT_BYTE_START, DICT_BYTE_START + MAX_BYTE_RANGE + 1):
            if int_to_byte(byte_key) in chars_unique:
                continue
            key: bytes = int_to_byte(byte_key)
        chuck_replaced: bytes = chunk.replace(max_freq[1], key)
        keymap = KeyMap(
            key=key,
            charpair=max_freq[1],
        )
    return (
        chuck_replaced,
        keymap,
    )  # reduced size 'hellllo' (size 7) -> 'heAAo' (size 5)
    #  dict size per mapping: 3 ('A','ll')


def chunk_pz_till_converge(
    chunk: bytes,
    max_iter: int = 100_000,
    verbose: bool = True,
) -> tuple[bytes, OrderedKeyMap]:
    """Compresses a string chunk to minimal size, including keymap size.

    Returns:
        tuple: (chunk_replaced, OrderedKeyMap(order: list[KeyMap]))"""
    orderedkeymap = OrderedKeyMap()
    sizelog_before = SizeLog(
        size_chunk=len(chunk),
        size_keymap=orderedkeymap.keymap_size,
    )

    for i_iter in range(max_iter):
        if verbose:
            print(
                f"Iter {i_iter} | Size before: {sizelog_before.size_total} | ", end=""
            )
        chunk, keymap = chunk_pz_once(chunk=chunk)
        if keymap.is_empty:
            break
        orderedkeymap.add_keymap(keymap=keymap)
        sizelog_curr = SizeLog(
            size_chunk=len(chunk),
            size_keymap=sizelog_before.size_keymap + 3,
        )
        if verbose:
            print(f"Size current: {sizelog_curr.size_total}")
        if sizelog_curr.size_total >= sizelog_before.size_total:
            break
        sizelog_before = sizelog_curr

    return (chunk, orderedkeymap)


def decompress_chunk_pz(
    chunk: bytes,
    orderedkeymap: OrderedKeyMap,
) -> bytes:
    if orderedkeymap.is_empty:
        assert chunk.isascii()
        return chunk
    for keymap in orderedkeymap.order[::-1]:
        if keymap.is_empty:
            continue
        chunk = chunk.replace(keymap.key, keymap.charpair)
    return chunk


@dataclass
class FormatChar:
    length: int = 1
    byte: int = DICT_BYTE_START


def find_format_char_for_strings(
    strings: list[bytes],
) -> FormatChar:
    """Find an ascii (exclusing RET, i.e., '\n') that does not appear in any of the strings given,
    if cannot find one, then startover and repeat itself once so that the fchar becomes
    2-dim, and so on and so forth (3-dim, 4-dim, ...).

    For example, query A? -> No -> B? -> No -> ... -> AA? -> No -> BB? -> ... -> AAA? -> ...

    Return:
        FormatChar.
    """
    fchar = FormatChar()
    while True:
        for string in strings:
            if (int_to_byte(fchar.byte) * fchar.length in string) or (
                int_to_byte(fchar.byte) == b"\n"
            ):
                if fchar.byte < DICT_BYTE_START + MAX_BYTE_RANGE - 1:
                    fchar.byte += 1
                else:
                    fchar.byte = DICT_BYTE_START
                    fchar.length += 1
                break  # break for loop
        else:  # Found one!
            break  # break while loop
    return fchar


def chunk_pz_format_string(
    chunks: list[bytes],
    orderedkeymaps: list[OrderedKeyMap],
) -> bytes:
    """Generate pz format string.
    1. Find a seperator format char (excluding RET '\n'), e.g., A.;
    2. Format compressed chunk like this:

    (line 1 for format char) A
    (line 2 and hereafter) AkcpxyzabcijkAcompressedtextAkcpxyzabcAanothertext
    first A: mark of key-cpair in a row, e.g., k is key, cp is cpair, and x is key,
    yz is cpair, ..., corresponding to encoding order;
    next A: mark of corresponding compressed text;
    further A's: mark of next chunk, and so on ...
    """
    result: bytes = b""
    fcharinfo: FormatChar = find_format_char_for_strings(strings=chunks)
    fchar: bytes = int_to_byte(fcharinfo.byte) * fcharinfo.length
    result += fchar + b"\n"
    for i in range(len(chunks)):
        if orderedkeymaps[i].is_empty:
            result += fchar + fchar + chunks[i]
            continue
        # Build keymaps
        result += fchar
        for keymap in orderedkeymaps[i].order:
            result += keymap.key
            result += keymap.charpair
        # Build text
        result += fchar + chunks[i]
    return result


def compress_to_string(
    chunks: list[bytes],
    verbose: bool = True,
) -> bytes:
    # chunks: list[bytes] = []
    # with open(filepath, "rb") as fi:
    #     read_string: bytes = b""
    #     read_string_set: set[bytes] = set()
    #     while True:
    #         this_char = fi.read(2)
    #         read_string_set.add(this_char)
    #         read_string += this_char
    #         if len(read_string_set) >= MAX_BYTE_RANGE - 3 or this_char == b"":
    #             read_string_set = set()
    #             chunks.append(read_string)
    #             read_string = b""
    #         if this_char == b"":
    #             break
    # if verbose:
    #     print("Done reading.")
    compressed_chunks: list[bytes] = []
    keymaps: list[OrderedKeyMap] = []
    for chunk in chunks:
        chunk_compressed, keymap = chunk_pz_till_converge(
            chunk=chunk,
            verbose=verbose,
        )
        compressed_chunks.append(chunk_compressed)
        keymaps.append(keymap)
    return chunk_pz_format_string(
        chunks=compressed_chunks,
        orderedkeymaps=keymaps,
    )


def io_compress_to_string(
    filepath: str,
    verbose: bool = True,
) -> bytes:
    chunks: list[bytes] = []
    with open(filepath, "rb") as fi:
        read_string: bytes = b""
        read_string_set: set[bytes] = set()
        while True:
            this_char = fi.read(2)
            read_string_set.add(this_char)
            read_string += this_char
            if len(read_string_set) >= MAX_BYTE_RANGE - 3 or this_char == b"":
                read_string_set = set()
                chunks.append(read_string)
                read_string = b""
            if this_char == b"":
                break
    if verbose:
        print("Done reading.")
    return compress_to_string(
        chunks=chunks,
        verbose=verbose,
    )


# def io_compress(
#     filepath: str,
# ) -> None:
#     """Print to stdout."""
#     print(
#         io_compress_to_string(
#             filepath=filepath,
#             verbose=False,
#         )
#     )
#     return


def is_even(integer: int) -> bool:
    return integer % 2 == 0


def read_orderedkeymap_from_string(keymap_string: bytes) -> OrderedKeyMap:
    assert len(keymap_string) % 3 == 0
    n_keymaps: int = len(keymap_string) // 3
    orderedkeymap: OrderedKeyMap = OrderedKeyMap()
    for i_keymap in range(n_keymaps):
        key: bytes = keymap_string[i_keymap * 3 : i_keymap * 3 + 1]
        charpair: bytes = keymap_string[i_keymap * 3 + 1 : i_keymap * 3 + 3]
        orderedkeymap.add_keymap(
            keymap=KeyMap(
                key=key,
                charpair=charpair,
            ),
        )
    return orderedkeymap


def decompress_to_string(
    string_formatted: bytes,
) -> bytes:
    fchar: bytes = b""
    string: bytes = b""
    iloc_string_start: int = 0
    # Parse fchar
    for iloc, _ in enumerate(string_formatted):
        char: bytes = string_formatted[iloc : iloc + 1]
        if char == b"\n":
            iloc_string_start = iloc + 1
            break
        else:
            fchar += char

    # Parse keymap and chunks
    string_formatted = string_formatted[iloc_string_start:]
    fields: list[bytes] = string_formatted.split(fchar)[
        1:
    ]  # Drop the first empty string
    assert is_even(len(fields))
    n_parts: int = len(fields) // 2
    for i_part in range(n_parts):
        keymap_string: bytes = fields[i_part * 2]
        chunk_string: bytes = fields[i_part * 2 + 1]
        keymap: OrderedKeyMap = read_orderedkeymap_from_string(
            keymap_string=keymap_string
        )
        string += decompress_chunk_pz(
            chunk=chunk_string,
            orderedkeymap=keymap,
        )
    return string


def io_decompress_to_string(
    filepath: str,
) -> bytes:
    with open(filepath, "rb") as fi:
        string_formatted: bytes = fi.read()
    return decompress_to_string(string_formatted=string_formatted)


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(
        description="Compress/Decompress a text file using char-pair",
    )
    parser.add_argument(
        "filepath",
        help="Path of text file to compress/decompress.",
    )
    parser.add_argument(
        "-d",
        "--decompress",
        help="Decompression mode. (Program defaults to compression mode.)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Specify path of output text.",
        required=True,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Print verbose information.",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()
    filepath: str = args.filepath
    decompress: bool = args.decompress
    output: str = args.output
    verbose: bool = args.verbose

    if not decompress:
        result: bytes = io_compress_to_string(
            filepath=filepath,
            verbose=True,
        )
        with open(output, "wb") as fo:
            fo.write(result)
    else:
        result: bytes = io_decompress_to_string(
            filepath=filepath,
        )
        with open(output, "wb") as fo:
            fo.write(result)
