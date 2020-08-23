======
Locker
======
Locker is a secure command-line based password and secret manager. It is built 
on top of common, widely available POSIX and open-source tools.

Features
--------
- Secure. Uses AES 256-bit encryption.

- Portable. Built on top of widely available POSIX tools.

- Shareable password databases. Each database's key is protected by asymmetric, 
  public/private key encryption. A database can be encrypted using multiple 
  public keys, meaning you can share each database with whomever you trust.

Requirements
------------
- Bash >= 5.0
- OpenSSL >= 1.1 (or LibreSSL >= 3.1)
- GNU core utils (``grep``, ``awk``, ``sed``, etc.)

Usage
-----

Setup
~~~~~
On first use you must initialize Locker and pick a suitable master password...

::

    $ locker init
    Pick a password for your private key:
    Confirm your password:
    Generating RSA private key, 2048 bit long modulus
    ........................+++++
    .............................+++++

By default, your master key will be stored in ``$HOME/.locker/``.

Now create a password database...

::

    $ locker newdb
    Database created at /home/me/.locker-db/

Adding and Retreiving Secrets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To add a new secret...

::

    $ locker add secret-name
    Enter pass phrase for /home/me/.locker/locker-key:
    Enter the secret's contents. Ctrl+D to finish
    This is a secret.
    Don't look!
    <...Ctrl+D...>

To decrypt a secret...

::

    $ locker get secret-name
    This is a secret.
    Don't look!

To list all the secrets stored in your database...

::

    $ locker
    secret-name
    ...

To search for secrets by name based on a pattern...

::

    $ locker find secret
    secret-name
    ...

How Locker Works
------------------
When a new `Locker` password database is created, a randomly generated 
database key is created. The database key is then encrypted with your 
`Locker` public key, meaning the database encryption key can only be 
decrypted with your `Locker` private key. Every secret added to the password 
database is encrypted using the database key.

When you decide to share the password database with someone you trust, 
the database key is re-encrypted with their public key (which they must 
share with you). For each person who can access the password database, 
the database key will be stored - encrypted by their public key - in the 
password database itself. This means every person who you share the
password database with can decrypt secrets using their own private key. No
master passwords are shared amonst users.

Alternatives to Locker
----------------------
- Pass_ - A project that is built on POSIX tools and provides very similar
  features. `Locker` takes a lot of inspiration from `Pass`. `Pass` uses
  GPG to provide encryption, which means sharing password databases 
  requires careful key management that can prove complicated for those 
  who are unfamiliar with GPG.

- 1password_ - A commercial, paid-for alternative that provides a Linux
  command-line feature.

.. _Pass: https://www.passwordstore.org/
.. _1password: https://1password.com/downloads/linux/
