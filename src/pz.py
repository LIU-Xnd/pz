DICT_ASCII_START: int = ord("A")
MAX_CHUNK_SIZE: int = 1000

from dataclasses import dataclass


@dataclass
class KeyMap:
    key: str | None = None
    charpair: str | None = None

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


def chunk_pz_once(chunk: str) -> tuple[str, KeyMap]:
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
    assert n_chars < MAX_CHUNK_SIZE
    counter: dict[str, int] = dict()
    max_freq: tuple[int, str] = (0, "")
    chars_unique: set[str] = set()
    for iloc_cpair in range(n_chars - 1):
        # str: 1234567  n_chars=7
        # idx: 0123456
        #           ^   last possible iloc
        cpair: str = chunk[iloc_cpair : iloc_cpair + 2]
        chars_unique.add(chunk[iloc_cpair])
        if cpair not in counter:
            counter[cpair] = 1
        else:
            counter[cpair] += 1
        if counter[cpair] > max_freq[0]:
            max_freq = (counter[cpair], cpair)
    if max_freq[0] <= 2:
        keymap = KeyMap()
        chuck_replaced: str = chunk
    else:
        for ascii_key in range(DICT_ASCII_START, DICT_ASCII_START + MAX_CHUNK_SIZE + 1):
            if chr(ascii_key) in chars_unique:
                continue
            key: str = chr(ascii_key)
        chuck_replaced: str = chunk.replace(max_freq[1], key)
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
    chunk: str,
    max_iter: int = 100_000,
    verbose: bool = True,
) -> tuple[str, OrderedKeyMap]:
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
    chunk: str,
    orderedkeymap: OrderedKeyMap,
) -> str:
    if orderedkeymap.is_empty:
        return chunk
    for keymap in orderedkeymap.order[::-1]:
        chunk = chunk.replace(keymap.key, keymap.charpair)
    return chunk


@dataclass
class FormatChar:
    length: int = 1
    ascii: int = DICT_ASCII_START


def find_format_char_for_strings(
    strings: list[str],
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
            if (chr(fchar.ascii) * fchar.length in string) or (
                chr(fchar.ascii) == "\n"
            ):
                if fchar.ascii < DICT_ASCII_START + MAX_CHUNK_SIZE:
                    fchar.ascii += 1
                else:
                    fchar.ascii = DICT_ASCII_START
                    fchar.length += 1
                break  # break for loop
        else:  # Found one!
            break  # break while loop
    return fchar


def chunk_pz_format_string(
    chunks: list[str],
    orderedkeymaps: list[OrderedKeyMap],
) -> str:
    """Generate pz format string.
    1. Find a seperator format char (excluding RET '\n'), e.g., A.;
    2. Format compressed chunk like this:

    (line 1 for format char) A
    (line 2 and hereafter) AkcpxyzabcijkAcompressedtextAkcpxyzabcAanothertext
    first A: mark of key-cpair in a row, e.g., k is key, cp is cpair, and x is key,
    yz is cpair, ..., corresponding to decoding order;
    next A: mark of corresponding compressed text;
    further A's: mark of next chunk, and so on ...
    """
    result: str = ""
    fcharinfo: FormatChar = find_format_char_for_strings(strings=chunks)
    fchar: str = chr(fcharinfo.ascii) * fcharinfo.length
    result += f"{fchar}\n"
    for i in range(len(chunks)):
        if orderedkeymaps[i].is_empty:
            result += f"{fchar}{fchar}{chunks[i]}"
            continue
        # Build keymaps
        result += f"{fchar}"
        for keymap in orderedkeymaps[i].order[::-1]:
            result += keymap.key
            result += keymap.charpair
        # Build text
        result += f"{fchar}{chunks[i]}"
    return result


def io_compress_to_string(
    filepath: str,
    verbose: bool = True,
) -> str:
    chunks: list[str] = []
    with open(filepath, "r") as fi:
        while True:
            chunks.append(fi.read(MAX_CHUNK_SIZE))
    compressed_chunks: list[str] = []
    keymaps: list[OrderedKeyMap] = []
    for chunk in chunks:
        chunk_compressed, keymap = chunk_pz_till_converge(
            chunk=chunk,
            verbose=verbose,
        )
        compressed_chunks.append(chunk_compressed)
        keymaps.append(keymap)
    return chunk_pz_format_string(
        chunks=chunks,
        orderedkeymaps=keymaps,
    )


def io_compress(
    filepath: str,
) -> None:
    """Print to stdout."""
    print(
        io_compress_to_string(
            filepath=filepath,
            verbose=False,
        )
    )
    return


def io_decompress_to_string(
    string_formatted: str,
) -> str:
    pass


def io_decompress(
    string_formatted: str,
) -> None:
    pass


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(
        description="Compress/Decompress a text file using char-pair",
    )
