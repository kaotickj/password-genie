### Password Genie
[![License](https://img.shields.io/badge/License-GPL3-blue.svg)](https://opensource.org/licenses/GPL-3.0) [![Version](https://img.shields.io/badge/Version-1.0.12-brightgreen.svg)](https://github.com/kaotickj/password-genie/releases/tag/v1.0.12)

Password Genie is a secure and user-friendly password management application built with Python and Tkinter. It allows users to generate strong passwords, hash and save passwords for various platforms, and retrieve them securely.

![Icon](password-genie.png)

##### Key Features:
- Password Generation: Create random and strong passwords based on user-defined criteria.
- Password Hashing: Hash passwords securely using SHA-256 for enhanced security.
- Password Storage: Safely store and retrieve passwords for different platforms in an encrypted format.
- Master Password Protection: Set and verify a master pass-key to ensure access control.

##### Usage:
Before you can use the password management features, you need to run the set-master-password utility. Thereafter, you will type your master password into the master key field and click the verify master password button to start being able to use the app. Once your master password is successfully entered, you can then generate strong passwords and assign them to platforms. Alternatively, you can save your existing passwords and their platforms for later retrieval in case you forget. All saved data is heavily encrypted, so is safe from prying eyes.

#### Python Library/Module Dependencies:
- `tkinter`
- `messagebox`
- `secrets`
- `string`
- `base64`
- `cryptography.hazmat.backends`
- `cryptography.hazmat.primitives`
- `cryptography.hazmat.primitives.hashes`
- `cryptography.hazmat.primitives.kdf.pbkdf2`
- `cryptography.fernet`

#### About the Author:
Password Genie is developed and maintained by Kaotick Jay, a seasoned cybersecurity professional with 30 years of experience. 

#### License:
Password Genie is licensed under GNU/GPL3. Feel free to contribute, modify, and distribute it in accordance with the terms of the license.
