# Introduction

This document provides guidance on integrating an OPTIGA™ TPM SLx 967x TPM 2.0 module into a Raspberry Pi to enable support for Linux Trusted and Encrypted Keys.

Trusted Keys rely on the presence of a TPM for enhanced security. In contrast, Encrypted Keys do not require a TPM but can be protected by a specified master key, which may either be a regular user key or a trusted key. Encrypted Keys are particularly useful in various subsystems, such as encrypted file systems and the Extended Verification Module (EVM), both of which are discussed in this document.

---

# Table of Contents

- **[Prerequisites](#prerequisites)**
- **[Building the Kernel](#building-the-kernel)**
- **[Raspberry Pi Configuration](#raspberry-pi-configuration)**
  - **[Enable TPM Support](#enable-tpm-support)**
  - **[Install TPM Software](#install-tpm-software)**
  - **[Provision TPM](#provision-tpm)**
  - **[Generate Trusted Key](#generate-trusted-key)**
  - **[Generate Disk Encryption Key](#generate-disk-encryption-key)**
  - **[Generate EVM Key](#generate-evm-key)**
  - **[Persist Keys](#persist-keys)**
- **[Keyctl Command Cheat Sheet](#keyctl-command-cheat-sheet)**
- **[Setting Up File-Level Disk Encryption](#setting-up-file-level-disk-encryption)**
- **[Setting Up Platform Integrity Protection](#setting-up-platform-integrity-protection)**
  - **[Modify the Kernel](#modify-the-kernel)**
  - **[Install Extended Attributes Tool](#install-extended-attributes-tool)**
  - **[IMA Appraisal](#ima-appraisal)**
    - **[IMA Appraisal Setup](#ima-appraisal-setup)**
    - **[IMA Appraisal Verification](#ima-appraisal-verification)**
  - **[EVM Appraisal](#evm-appraisal)**
    - **[EVM Appraisal Setup](#evm-appraisal-setup)**
    - **[EVM Appraisal Verification](#evm-appraisal-verification)**
- **[License](#license)**

---

# Prerequisites

Prerequisites:
- A [Raspberry Pi 4](https://www.raspberrypi.org/products/raspberry-pi-4-model-b/)
- A microSD card (>=8GB) flashed with Raspberry Pi OS. Download the official image from [raspbian-2020-08-24](https://downloads.raspberrypi.org/raspios_armhf/images/raspios_armhf-2020-08-24)
- One of the following TPM2.0 boards:
  - [IRIDIUM9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/)
  - [OPTIGA™ TPM SLB 9672 RPI evaluation board](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-tpm-9672-rpi-eval/)
- A host machine running Ubuntu 18.04 LTS.

---

# Building the Kernel

This section explains how to rebuild the Raspberry Pi Linux kernel from source to enable Trusted Keys and Encrypted Keys functionalities.

Install required dependencies on the host machine:
```
$ sudo apt install git bc bison flex libssl-dev make libc6-dev libncurses5-dev libncurses5-dev
```

Download this repository for later use:
```
$ git clone https://github.com/Infineon/linux-trusted-key-optiga-tpm ~/linux-trusted-key-optiga-tpm
```

Install the toolchain and set the environment variable:
```
$ git clone https://github.com/raspberrypi/tools ~/tools
$ export PATH=$PATH:~/tools/arm-bcm2708/arm-linux-gnueabihf/bin
```

Download the Linux kernel source:
```
$ git clone -b rpi-5.4.y https://github.com/raspberrypi/linux ~/linux
$ cd ~/linux
$ git checkout raspberrypi-kernel_1.20200902-1
```

Build instructions:
```
# Prepare
$ KERNEL=kernel7l
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- bcm2711_defconfig

# Configure
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- menuconfig

  Security options --->
    <M> TRUSTED KEYS
    <M> ENCRYPTED KEYS

# Build
$ make -j$(nproc) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs
```

Transfer the kernel modules, kernel image, and device tree blobs to the SD card (ensure to replace `/dev/sdbX` and `/dev/sdbY` with the correct device identifiers):
```
$ mkdir mnt
$ mkdir mnt/fat32
$ mkdir mnt/ext4
$ sudo umount /dev/sdbX
$ sudo umount /dev/sdbY
$ sudo mount /dev/sdbX mnt/fat32
$ sudo mount /dev/sdbY mnt/ext4
$ sudo env PATH=$PATH make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- INSTALL_MOD_PATH=mnt/ext4 modules_install
$ sudo cp mnt/fat32/$KERNEL.img mnt/fat32/$KERNEL-backup.img
$ sudo cp arch/arm/boot/zImage mnt/fat32/$KERNEL.img
$ sudo cp arch/arm/boot/dts/*.dtb mnt/fat32/
$ sudo cp arch/arm/boot/dts/overlays/*.dtb* mnt/fat32/overlays/
$ sudo cp arch/arm/boot/dts/overlays/README mnt/fat32/overlays/
$ sudo umount mnt/fat32
$ sudo umount mnt/ext4
$ sync
```

---

# Raspberry Pi Configuration

This section outlines the steps to install and enable all the necessary software and features on a Raspberry Pi.

## Enable TPM Support

Insert the SD card and boot into Raspberry Pi OS.

Open the file `/boot/config.txt` and add the following lines:
```
dtoverlay=tpm-slb9670
```

Reboot the system to apply the changes:
```
$ reboot
```

Run the following command to check if the TPM is active:
```
$ ls /dev | grep tpm
tpm0
tpmrm0
```

## Install TPM Software

This section covers building and installing TPM software from source.

Install the required dependencies:
```
$ sudo apt update
$ sudo apt -y install autoconf-archive libcmocka0 libcmocka-dev procps iproute2 \
  build-essential git pkg-config gcc libtool automake libssl-dev uthash-dev autoconf \
  doxygen libgcrypt-dev libjson-c-dev libcurl4-gnutls-dev uuid-dev pandoc
```

Download, build, and install TPM software stack:
```
$ cd ~
$ git clone https://github.com/tpm2-software/tpm2-tss.git
$ cd tpm2-tss
$ git checkout 3.0.3
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Download, build, and install TPM tools:
```
$ cd ~
$ git clone https://github.com/tpm2-software/tpm2-tools.git
$ cd tpm2-tools
$ git checkout 5.0
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

## Provision TPM

Authorize non-privileged access to TPM device node:
```
$ sudo chmod a+rw /dev/tpmrm0
```

Clear the TPM:
```
$ tpm2_clear -c p
```

Create a primary key and store it as a persistent key. Ensure the authorization value is set to 40 hexadecimal characters for `keyctl` to function correctly:
```
$ tpm2_createprimary -c primary.ctx -G ecc -p hex:0123456789abcdef0123456789abcdef01234567
$ tpm2_evictcontrol -C o -c primary.ctx 0x81000001
```

## Generate Trusted Key

Generate a TPM-protected Kernel Master Key (KMK):
```
$ sudo modprobe trusted
$ keyctl add trusted kmk "new 32 keyhandle=0x81000001 keyauth=0123456789abcdef0123456789abcdef01234567" @s
$ keyctl show @s
```

## Generate Disk Encryption Key

Generate a KMK-protected Disk Encryption Key (DEK). Ensure the description is set to 16 hexadecimal characters to ensure compatibility with eCryptfs:
```
$ sudo modprobe encrypted-keys
$ keyctl add encrypted 0123456789abcdef "new ecryptfs trusted:kmk 64" @s
$ keyctl show @s
```

## Generate EVM Key

Generate a KMK-protected EVM key:
```
$ sudo modprobe encrypted-keys
$ keyctl add encrypted evm-key "new trusted:kmk 32" @s
$ keyctl show @s
```

## Persist Keys

Create a directory to store the key backups:
```
$ mkdir ~/keys
```

Backup the KMK, DEK, and EVM keys:
```
$ keyctl pipe `keyctl search @s trusted kmk` > ~/keys/kmk.blob
$ keyctl pipe `keyctl search @s encrypted 0123456789abcdef` > ~/keys/dek.blob
$ keyctl pipe `keyctl search @s encrypted evm-key` > ~/keys/evm-key.blob
```

Restore the keys after a system reboot:
```
$ sudo modprobe trusted
$ keyctl add trusted kmk "load `cat ~/keys/kmk.blob` keyhandle=0x81000001 keyauth=0123456789abcdef0123456789abcdef01234567" @s

$ sudo modprobe encrypted-keys
$ keyctl add encrypted 0123456789abcdef "load `cat ~/keys/dek.blob`" @s
$ keyctl add encrypted evm-key "load `cat ~/keys/evm-key.blob`" @s

$ keyctl show @s
```

---

# Keyctl Command Cheat Sheet

Keyctl is a command-line tool that enables users to manage and manipulate keys on a Linux system. The following table provides a list of useful commands:
| Command                                   | Description                                                                                                      |
|-------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `keyctl clear @s`                         | Clears all keys attached to the session keyring.                                                                 |
| `keyctl unlink <key>`                     | Removes a specific key from all associated keyrings.                                                             |
| `keyctl show @s`                          | Lists the keys and keyrings currently attached to the session keyring.                                           |
| `keyctl add user kmk "password" @s`       | Creates a plain key with the following properties:<br>- **Key type**: user<br>- **Description**: "kmk"<br>- **Data**: "password"<br>- **Keyring**: session keyring |
| `keyctl add trusted kmk "new 32 keyhandle=0x81000001 keyauth=<auth-value>" @s` | Creates a TPM-protected key with the following properties:<br>- **Key type**: trusted<br>- **Description**: "kmk"<br>- **Data**: 32 bytes of random numbers<br>- **Sealed by TPM key handle**: 0x81000001<br>- **Authorization value**: 40-byte hexadecimal<br>- **Keyring**: session keyring |
| `keyctl add encrypted enc-key "new user:kmk 32" @s` | Creates an encrypted key secured by a specified master key. The key has the following properties:<br>- **Key type**: encrypted<br>- **Description**: "enc-key"<br>- **Data**: 32 bytes of random numbers<br>- **Secured by Master Key**: "kmk"<br>- **Keyring**: session keyring |
| `keyctl search @s user kmk`               | Searches the session keyring (`@s`) for a key of type `user` with the description `kmk`. If found, returns the key ID. |
| `keyctl print <key>`                      | Displays the data field of the specified key.                                                                    |
| `keyctl pipe <key> > key.blob`            | Exports a key to a file (`key.blob`) for backup purposes.                                                        |
| ``keyctl add <key-type> <description> "load `cat ~/key.blob`" @s`` | Restores a backed-up key. This method is applicable only for `trusted` and `encrypted` key types. |

---

# Setting Up File-Level Disk Encryption

This section explains how to use the DEK to configure filesystem-level disk encryption using the eCryptfs utility.

Install eCryptfs utilities:
```
$ sudo apt install ecryptfs-utils
```

Create a workspace directory:
```
$ mkdir ~/vault
```

Mount the directory as an eCryptfs filesystem:
```
$ sudo mount -i -t ecryptfs -o ecryptfs_sig=0123456789abcdef,ecryptfs_fnek_sig=0123456789abcdef,ecryptfs_cipher=aes,ecryptfs_key_bytes=32 ~/vault ~/vault
```

Create a file in the encrypted directory
```
$ echo "secret" > ~/vault/data
$ xxd ~/vault/data
00000000: 7365 6372 6574 0a secret.
```

Unmount the filesystem and observe the changes, both the filename and the content are now encrypted:
```
$ sudo umount ~/vault

$ ls ~/vault
CRYPTFS_FNEK_ENCRYPTED.FWY...

$ xxd ~/vault/ECRYPTFS_FNEK_ENCRYPTED.FWY...
00000000: 0000 0000 0000 0007 b245 eee8 8ec4 591d .........E....Y.
00000010: 0300 000a 0000 1000 0002 8c2d 0409 0301 ...........-....
00000020: 0000 0000 0000 0000 605a ec8c 8901 0c03 ........`Z......
00000030: 6fa9 8896 e23c 8fa3 ca63 ed0a 7de9 9859 o....<...c..}..Y
00000040: 2dd5 6938 d1a9 81d0 36ed 1662 085f 434f -.i8....6..b._CO
00000050: 4e53 4f4c 4500 0000 0001 2345 6789 abcd NSOLE.....#Eg...
...
```

Remount the directory as an eCryptfs filesystem to restore access to the file.

---

# Setting Up Platform Integrity Protection

This section details how an EVM key integrates with the Linux IMA and EVM subsystems to safeguard platform integrity.

The **IMA (Integrity Measurement Architecture)** subsystem is responsible for verifying the integrity of file contents by comparing a file's measurement against a known "good" value stored in its extended attribute (e.g., `security.ima`).

The **EVM (Extended Verification Module)** subsystem ensures the integrity of security-sensitive extended attributes, such as `security.ima`, by using the EVM key. This enables the detection of unauthorized offline tampering with files and their metadata.

## Modify the Kernel

Apply the patch using the following commands:
```
$ cd ~/linux
$ git am ~/linux-trusted-key-optiga-tpm/patches/code-listing-39-40-41.patch
```

Patch details:
- **`security/integrity/ima/ima_policy.c`**:
  This modification restricts IMA/EVM appraisal to files owned by the root user and only when executed by root.
  > The purpose of this change is to simplify operations for demonstration and testing purposes only.
- **`drivers/clk/bcm/clk-bcm2835.c`**:
  IMA/EVM appraisals can be triggered during the early boot process, requiring the TPM and SPI subsystems to be available beforehand.

Reconfigure the kernel before building:
> Note that the following modules must be configured as built-in modules (`*`) instead of loadable modules (`M`).
```
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- menuconfig

  Device Drivers --->
    [*] SPI support --->
      <*> BCM2835 SPI controller
    Character devices --->
      -*- TPM Hardware Support --->
        <*> TPM Interface Specification 1.3 Interface / TPM 2.0 FIFO Interface – (SPI)

  Security options --->
    <*> TRUSTED KEYS
    -*- ENCRYPTED KEYS
    [*] Enable different security models
    -*- Enable the securityfs filesystem
    [*] Integrity subsystem
    [*]   Integrity Measurement Architecture(IMA)
    [*]     Appraise integrity measurements
    [*]   ima_appraise boot parameter
    [*] EVM support
    [*] FSUUID (version 2)
```

Revisit the instructions in the [Building the Kernel](#building-the-kernel) section to build and transfer the kernel image.

After flashing the image, boot the Raspberry Pi and modify the boot parameters by running:
```
$ sudo nano /boot/cmdline.txt
```

Append the following parameter to the existing line:
```
ima_policy=tcb
```

Reboot the Raspberry Pi and check if IMA and TPM is activated. The output value must be greater than 1:
```
$ sudo cat /sys/kernel/security/ima/runtime_measurements_count

$ ls /dev | grep tpm
tpm0
tpmrm0
```

## Install Extended Attributes Tool

Install the required package for managing extended attributes:
```
$ sudo apt install attr
```

Check the installed version to confirm successful installation:
```
$ getfattr --version
getfattr 2.4.48
```

## IMA Appraisal

The IMA appraisal feature enables a local system to verify the integrity of files, ensuring they have not been tampered with.

### IMA Appraisal Setup

To enable IMA appraisal, the filesystem must first be labeled with the extended attribute `security.ima`. This can be achieved by modifying the kernel boot parameters (`/boot/cmdline.txt`):
```
ima_policy=appraise_tcb ima_appraise=fix
```

Reboot the Raspberry Pi and verify if IMA labeling is active by checking for the `security.ima` extended attribute using the `getfattr` utility.
```
$ sudo su -c "echo 'hello world' > data"
$ getfattr -de hex -m - data
# file: data
security.ima=0x0122596363b3de40b06f981fb85d82312e8c0ed511
```

Run the following command to label the filesystem. Only files that comply with the defined policies will be labeled. Please note that this process may take some time to complete:
```
$ sudo su -c "time find / -fstype ext4 -type f -uid 0 -exec dd if='{}' of=/dev/null count=0 status=none \;"
```

With the filesystem now labeled, reactivate IMA appraisal by modifying the kernel boot parameters (`/boot/cmdline.txt`):
```
ima_policy=appraise_tcb ima_appraise=enforce
```

Reboot the Raspberry Pi.

### IMA Appraisal Verification

To demonstrate IMA appraisal's response to a file tampering attack, create a root-owned file and allow a non-root user to edit it (for testing purposes only). Since the specified policies do not trigger appraisal for non-root user actions, the extended attribute will not be updated when a non-root user modifies the file, simulating an attack. As a result, when the root user attempts to access the file, the appraisal will fail, rendering the file inaccessible and preventing any further damage:
```
$ cd ~
$ sudo rm data
$ sudo su -c "echo 'hello world' > data"

$ getfattr -de hex -m - data
# file: data
security.ima=0x0122596363b3de40b06f981fb85d82312e8c0ed511

$ sudo cat data
hello world

$ sudo chmod a+w data
$ echo "world hello" >> data

$ getfattr -de hex -m - data
# file: data
security.ima=0x0122596363b3de40b06f981fb85d82312e8c0ed511

$ sudo cat data
cat: data: Permission denied
```

## EVM Appraisal

EVM appraisal protects the IMA extended attribute against attacks, including offline tampering, by leveraging a KMK-protected EVM key.

### EVM Appraisal Setup

For EVM appraisal to work, both the KMK and the EVM key must be loaded into the keyring prior to EVM activation. This is facilitated by initramfs, a minimal filesystem used during the boot process. Initramfs ensures that the keyring is populated and EVM is activated before the root filesystem (rootfs) is mounted, thereby securing the system early in the boot sequence.

An initramfs image can be created using the initramfs-tools utility. Follow these steps:

1. Download this repository:
    ```
     $ git clone https://github.com/Infineon/linux-trusted-key-optiga-tpm ~/linux-trusted-key-optiga-tpm
    ```
2. Hook scripts specify which files should be included in the initramfs image. Note that the hook scripts themselves are not included in the image:
     ```
     $ cp ~/linux-trusted-key-optiga-tpm/initramfs-tools/ima-hook /etc/initramfs-tools/hooks/ima-hook
     ```
3. Boot scripts are executed during the initramfs boot process. These scripts are included in the initramfs image and are responsible for loading the KMK and EVM keys before enabling EVM:
     ```
     $ cp ~/linux-trusted-key-optiga-tpm/initramfs-tools/ima-boot /etc/initramfs-tools/scripts/local-top/ima-boot
     ```
4. Make the scripts executable:
    ```
    $ sudo chmod a+x /etc/initramfs-tools/hooks/ima-hook
    $ sudo chmod a+x /etc/initramfs-tools/scripts/local-top/ima-boot
    ```
5. Disable IMA appraisal by modifying the kernel boot parameters (`/boot/cmdline.txt`). Since the file is inaccessible within Raspberry Pi OS due to IMA appraisal being in enforcement mode, access it externally using a microSD card reader:
    ```
    ima_policy=appraise_tcb ima_appraise=fix evm=fix
    ```
6. Boot the Raspberry Pi and create an initramfs image in the `/boot` directory:
    ```
    $ sudo update-initramfs -c -k $(uname -r)
    ```
7. Verify the initramfs image by ensuring that the keys and boot script have been successfully included:
    ```
    $ mkdir ~/initramfs
    $ cd ~/initramfs
    $ zcat /boot/initrd.img-5.4.51-v7l+ | cpio -idmv

    $ ls etc/keys/
    evm-key.blob kmk.blob

    $ ls scripts/local-top/
    ima-boot ORDER
    ```
8. Add the following lines to the kernel configuration file (`/boot/config.txt`):
    ```
    initramfs initrd.img-5.4.51-v7l+
    ```
9. Reboot the Raspberry Pi and verify that EVM has been activated:
    ```
    $ sudo cat /sys/kernel/security/evm
    1
    ```
10. Run the following command to label the filesystem. Only files that comply with the defined policies will be labeled. Please note that this process may take some time to complete:
    ```
    $ sudo su -c "time find / -fstype ext4 -type f -uid 0 -exec dd if='{}' of=/dev/null count=0 status=none \;"
    ```
11. Enable IMA and EVM appraisal by modifying the kernel boot parameters (`/boot/cmdline.txt`) as shown below, excluding the `evm=fix` option:
    ```
    ima_policy=appraise_tcb ima_appraise=enforce
    ```
12. Reboot the Raspberry Pi.

### EVM Appraisal Verification

With EVM machanism enabled, create a file. The file will be accessible without any issues, and the newly added extended attribute `security.evm` can be viewed using the following command:
```
$ cd ~
$ sudo rm data
$ sudo su -c "echo 'hello world' > data"

$ getfattr -de hex -m - data
# file: data
security.evm=0x0284513b42309bf4f084203396853df0edb5c9a1bf
security.ima=0x0122596363b3de40b06f981fb85d82312e8c0ed511

$ sudo cat data
hello world
```

To demonstrate the effect of EVM enforcement, first disable it by editing the kernel configuration and boot parameters. These files cannot be accessed from within Raspberry Pi OS due to IMA and EVM appraisal being in enforcement mode. Instead, access them externally using a microSD card reader. Make the following modifications:
- `/boot/config.txt`:
  ```
  #initramfs initrd.img-5.4.51-v7l+
  ```
- `/boot/cmdline.txt`:
  ```
  ima_policy=appraise_tcb ima_appraise=fix evm=fix
  ```

Reboot the Raspberry Pi and verify if EVM is disabled by checking the following command output:
```
$ sudo cat /sys/kernel/security/evm
0
```

To demonstrate EVM appraisal's response to a file tampering attack, execute the following command to corrupt the EVM attribute. While the IMA attribute tracks file content, the EVM attribute monitors file metadata, including ownership and extended attributes. Note that the EVM attribute remains unchanged despite the group ownership change because EVM is disabled, leading to an inconsistent EVM attribute value:
```
$ cd ~
$ sudo chgrp pi data

$ getfattr -de hex -m - data
# file: data
security.evm=0x0284513b42309bf4f084203396853df0edb5c9a1bf
security.ima=0x0122596363b3de40b06f981fb85d82312e8c0ed511
```

To reactivate EVM, update the following files:
- `/boot/config.txt`:  
  Add or ensure the following line is present:
  ```
  initramfs initrd.img-5.4.51-v7l+
  ```
- `/boot/cmdline.txt`:  
  Remove `evm=fix` and update the parameters as follows:
  ```
  ima_policy=appraise_tcb ima_appraise=enforce
  ```

Reboot the Raspberry Pi and observe that the file is no longer accessible due to the inconsistent EVM attribute value, as enforced by the EVM mechanism:
```
$ sudo cat ~/data
cat: data: Permission denied
```

---

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.