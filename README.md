# firolock

firolock is a secure software that ensures your data remains 100% safe and encrypted. With firolock, you have exclusive access to your keys and data, providing an added layer of security and privacy.

## Features

* Generation:
  * Generates a random and safe key and saves it in a specified file.
* Encryption:
  * Encrypts files using a key file and saves the encrypted data in a specified output file.
* Decryption:
  * Decrypts files using a key file and saves the decrypted data in a specified output file.

## Instalation

<details><summary><b>Linux</b></summary>

<details open><summary><i>Installation with firolock installer</i></summary><br>
On linux firolock can be installed with its <a href="https://github.com/Ctrl-AltElite/firolock/releases/download/v0.1.2/firolock_0.1.2-1_amd64.deb">installer</a>
</details>

<details><summary><i>Installation with firolock shell installer</i></summary><br>
NOTE: These commands require super-user (sudo) permissions

1. Open a terminal and type the following commands in the terminal
2. Install curl (usually comes pre-installed)

```bash
sudo apt-get install curl
```

3. Run firolock installer

```bash
curl https://github.com/Ctrl-AltElite/firolock/blob/master/installers/linux.sh | sudo sh
```

</details>

<details><summary><i>Compiling from source</i></summary><br>

1. Open a terminal and type the following commands in the terminal

```bash
# IMPORTANT: make sure you have git, make, g++ and libssl-dev installed
# if not you can install them with the following command
# sudo apt install g++ libssl-dev make git

git clone https://github.com/Ctrl-AltElite/firolock.git
cd firolock
make
sudo make install

# If you want to unsintsall firolock you can run the following command
# sudo make uninstall
```

</details>
</details>

<details><summary><b>Windows</b></summary>
<details open><summary><i>Installation with firolock installer</i></summary><br>
On windows firolock can be installed with its <a href="https://github.com/Ctrl-AltElite/firolock/releases/download/v0.1.2/firolock_0.1.2-1_amd64.exe">installer</a>
</details>
</details>

## Usage

To use firolock, follow the instructions below:

1. Generation:

```bash
./firolock g <output file>
```

* Generates a random and safe key and saves it in the specified `<output file>`. Example: `./firolock g master.key`

2. Encryption:

```bash
./firolock e <key file> <input file> <output file>
```

* Encrypts the `<input file>` using the key stored in the `<key file>` and saves the encrypted data in the `<output file>`. Example: `./firolock e master.key data.txt encrypted.bin`

3. Decryption:

```bash
./firolock d <key file> <input file> <output file>
```

* Decrypts the `<input file>` using the key stored in the `<key file>` and saves the decrypted data in the `<output file>`. Example: `./firolock d master.key encrypted.bin data.dec`

## File Types

* `<key file>`: Text/binary file containing the encryption key.
* `<input file>` and `<output file>`: Can be any file type.

## Security Note

firolock is designed to keep your data secure and encrypted. Remember to keep your `<key file>` safe and confidential as it is crucial for decryption. Losing or exposing the `<key file>` may result in permanent data loss.

## Current version

v0.1.2

### Fixes

* README install instructions now work correctly
* Linux shell installer now works correctly

## License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
