# AES Implementation in C

This is a simplified implementation of the Advanced Encryption Standard (AES) in C with a fixed key size of 16 bits. The program can operate either by launching it and choosing the operation interactively or by using command-line arguments.

## Usage

To use the program, you can either launch it without any arguments for interactive mode or provide command-line arguments for automation.

### Interactive Mode

```bash
./aes
```

Launching the program without any arguments will prompt you to choose the operation (encryption or decryption), enter the key, and then provide the ciphertext or plaintext, depending on the chosen operation.

```bash
Please enter operation:
1.ENCODE
2.DECODE
```


### Command-Line Mode

```bash
./aes OPERATION KEY DATA
```

- `OPERATION`: Specify the operation as either "ENC" for encryption or "DEC" for decryption.
- `KEY`: Enter the encryption/decryption key as a 4-character hexadecimal string (e.g., "2b7e").
- `DATA`: Provide the ciphertext for encryption or plaintext for decryption as a 4-character hexadecimal string (e.g., "3243").

## Example

### Encryption

```bash
./aes ENC 4AF5 D728
```

### Decryption

```bash
./aes DEC 4AF5 24EC
```

## Building

To build the program, use the gcc compiler or any other compiler of your choice.

```bash
gcc main.c aes.exe
```
or you can use the provided makefile by just makes

```bash
make
```
## Dependencies

The program has no external dependencies and no external libraries has been used.
