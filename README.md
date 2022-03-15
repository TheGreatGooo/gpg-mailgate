# GPG Lacre Project

Fork and continuation of original work of gpg-mailgate project: https://github.com/fkrone/gpg-mailgate


**GPG Lacre** (wax seal in Portuguese) is a content filter for Postfix that automatically encrypts unencrypted incoming email using PGP or S/MIME for select recipients.
This project is the continuation of the work of "gpg-mailgate" on providing open source, GnuPG based email encryption for emails at rest. All incoming emails are automatically encrypted with user's public key before they are saved on the server. It is a server side encryption solution while the control of the encryption keys are fully at the hands of the end-user and private keys are never stored on the server.

The scope of the project is to improve on the already existing code, provide easy to use key upload system (standalone as well as Roundcube plugin) and key discoverability. Beside providing a solution that is easy to use we will also provide easy to digest material about encryption, how it works and how to make use of it in situations other the just mailbox encryption. Understanding how encryption works is the key to self-determination and is therefore an important part of the project.

GPG Lacre will be battle tested on the email infrastructure of https://disroot.org (an ethical non-profit service provider).

---

The work on this project in 2021 is funded by https://nlnet.nl/thema/NGIZeroPET.html for which we are very thankful.

The scope of the work for 2021 is:
 - Rewrite code to python3
 - Improve standalone key upload website
 - Provide Roundcube plugin for key management
 - Improve key server features
 - Provide webiste with information and tutorials on how to use GPG in general and also **Lacre**
 - (Optional) provide Autocrypt support

Made possible thanks to:<br>
![](https://nlnet.nl/logo/banner.png)

---
For installation instructions, please refer to the included **INSTALL** file.

---

# Features
- Correctly displays attachments and general email content; currently will only display first part of multipart messages
- Public keys are stored in a dedicated gpg-home-directory
- Encrypts both matching incoming and outgoing mail (this means gpg-mailgate can be used to encrypt outgoing mail for software that doesn't support PGP or S/MIME)
- Decrypts PGP encrypted mails for present private keys (but no signature check and it does not always work with PGP/INLINE encrypted mails)
- Easy installation
- gpg-mailgate-web extension is a web interface allowing any user to upload PGP keys so that emails sent to them from your mail server will be encrypted (see gpg-mailgate-web directory for details)
- people can submit their public key like to any keyserver to gpg-mailgate with the gpg-mailgate-web extension
- people can send an S/MIME signed email to register@yourdomain.tld to register their public key
- people can send their public OpenPGP key as attachment or inline to register@yourdomain.tld to register it

This is forked from the original project at http://code.google.com/p/gpg-mailgate/

# Authors

This is a combined work of many developers and contributors. We would like to pay honours to original gpg mailbox developers for making this project happen, and providing solid solution for encryption emails at rest:

* mcmaster <mcmaster@aphrodite.hurricanelabs.rsoc>
* Igor Rzegocki <ajgon@irgon.com> - [GitHub](https://github.com/ajgon/gpg-mailgate)
* Favyen Bastani <fbastani@perennate.com> - [GitHub](https://github.com/uakfdotb/gpg-mailgate)
* Colin Moller <colin@unixarmy.com> - [GitHub](https://github.com/LeftyBC/gpg-mailgate)
* Taylor Hornby <havoc@defuse.ca> - [GitHub](https://github.com/defuse/gpg-mailgate)
* Martin (uragit) <uragit@telemage.com> - [GitHub](https://github.com/uragit/gpg-mailgate)
* Braden Thomas - [BitBucket](https://bitbucket.org/drspringfield/emailencrypt.net/)
* Bruce Markey - [GitHub](https://github.com/TheEd1tor)
* Remko Tronçon - [GitHub](https://github.com/remko/phkp/)
* Kiritan Flux [GitHub](https://github.com/kflux)
* Fabian Krone [GitHub] (https://github.com/fkrone/gpg-mailgate)
