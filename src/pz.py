DICT_ASCII_START: int = ord(" ")  # 32
MAX_CHUNK_SIZE: int = 1300


def chunk_pz_once(chunk: str):
    """Compress a chunk of string for one iteration.
    1. Find the most frequent char-pair, e.g. xx;
    2. Find a not-used char as key, e.g. A;
    3. Create a mapping A -> xx.

    Example:
    Sentence: How about your cow? -> Counter(ow: 2, ou:2, ...);
    A in Sentence? -> No -> Mapping: A -> ow.

    Return:
        tuple: (chunk_compressed: str, key: str, charpair: str)
    """

    n_chars: int = len(chunk)
    assert n_chars >= 2
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
    for ascii_key in range(DICT_ASCII_START, DICT_ASCII_START + MAX_CHUNK_SIZE + 1):
        if chr(ascii_key) in chars_unique:
            continue
        key: str = chr(ascii_key)
    chuck_replaced: str = chunk.replace(max_freq[1], key)
    return (
        chuck_replaced,
        key,
        max_freq[1],
    )  # reduced size 'hellllo' (size 7) -> 'heAAo' (size 5)
    #  dict size per mapping: 3 ('A','ll')
