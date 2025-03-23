# Pair-Zipping (pz) for Text Files

# Get Started

## Download and Install
```Bash
$ cd ~
$ git clone https://github.com/LIU-Xnd/pz.git
$ export pz='python ~/pz/src/pz.py'
```
For help, see
```Bash
$ pz -h
```

## Compress 
```Bash
$ pz input-text.txt -o output.pz
```

## Decompress
```Bash
$ pz input-compressed.pz -o output-decompressd.txt -d
```

# Example
```Bash
$ cd ~/pz/demo/
$ pz raw.txt -o compressed.pz
$ ls -lh
# 3.3K raw.txt
# 2.4K compressed.pz
```