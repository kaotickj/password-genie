### Password Genie
[![License](https://img.shields.io/badge/License-GPL3-blue.svg)](https://opensource.org/licenses/GPL-3.0) [![Version](https://img.shields.io/badge/Version-1.0.12-brightgreen.svg)](https://github.com/kaotickj/password-genie/releases/tag/v1.0.12)

Password Genie is a secure and user-friendly password management application built with Python and Tkinter. It allows users to generate strong passwords, hash and save passwords for various platforms, and retrieve them securely.

![Icon](password-genie.png)

##### Key Features:
- **Password Generation:** Create random and strong passwords based on user-defined criteria.
- **Password Hashing:** Hash passwords securely using SHA-256 for enhanced security.
- **Password Storage:** Safely store and retrieve passwords for different platforms in an encrypted format.
- **Master Password Protection:** Set and verify a master pass-key to ensure access control.

##### Usage:
- Set Master Password: Run the "set-master-password" utility to establish your master password.
- Verify Master Password: Enter your master password in the designated field and click "Verify Master Password" to unlock the app.
- Generate Strong Passwords: Once your master password is verified, generate robust passwords tailored to your criteria.
- Assign to Platforms: Link generated passwords to specific platforms for organized password management.
- Save Passwords: Safely store existing passwords and their associated platforms for future retrieval.
- Encryption Security: All saved data undergoes robust encryption, ensuring it remains confidential and secure.
- Caution: Your master password serves as the encryption key; changing it after setting will make it impossible to retrieve saved passwords.

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
Password Genie is licensed under [GNU/GPL3](LICENSE). Feel free to contribute, modify, and distribute it in accordance with the terms of the license.

#### [Code of Conduct](CODE_OF_CONDUCT.md) | [Contributing Guidelines](CONTRIBUTING.md)
