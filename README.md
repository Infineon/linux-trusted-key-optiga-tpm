# Introduction

This document explains how an OPTIGA™ TPM SLx 9670 TPM2.0 can be integrated into a Raspberry Pi® to
enable the Linux Trusted and Encrypted Keys.

Trusted Keys require the availability of a TPM to function for added security, while Encrypted Keys do not
depend on a TPM but it can be protected by a specified master key. A master key can be a regular user-key or a
trusted-key type. Encrypted Keys can be used by some useful subsystems, e.g., encrypted file system and
Extended Verification Module (EVM), both will be covered in this document.

# Prerequisites

Hardware prerequisites:
- [Raspberry Pi® 4](https://www.raspberrypi.org/products/raspberry-pi-4-model-b/)
- [IRIDIUM9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/)\
  <img src="https://github.com/Infineon/linux-trusted-key-optiga-tpm/raw/main/media/IRIDIUM9670-TPM2.png" width="30%">

# Getting Started

For detailed setup and information, please find the Application Note at [link](https://github.com/Infineon/linux-trusted-key-optiga-tpm/raw/main/documents/tpm-appnote-linux-trusted-keys.pdf).

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.