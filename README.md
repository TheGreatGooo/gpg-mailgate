# gpg-mailgate

gpg-mailgate is a content filter for Postfix that automatically encrypts unencrypted incoming email using PGP for select recipients.

* added HKP keyserver key submit function to the gpg-mailgate-web script
* added S/MIME support (borrowed from drspringfield's https://bitbucket.org/drspringfield/emailencrypt.net/)

For installation instructions, please refer to the included INSTALL file.

# Features
- Correctly displays attachments and general email content; currently will only display first part of multipart messages
- Public keys can be stored in a dedicated gpg-home-directory (see Note 1 in INSTALL)
- Encrypts both matching incoming and outgoing mail (this means gpg-mailgate can be used to encrypt outgoing mail for software that doesn't support PGP)
- Easy installation
- gpg-mailgate-web extension is a web interface allowing any user to upload PGP keys so that emails sent to them from your mail server will be encrypted (see gpg-mailgate-web directory for details)
- people can submit their public key like to any keyserver to gpg-mailgate
- people can send an S/MIME signed email to register@yourdomain.tld to register their public key

This is forked from the original project at http://code.google.com/p/gpg-mailgate/

# Authors

This is a combined work of many developers:

* mcmaster <mcmaster@aphrodite.hurricanelabs.rsoc>
* Igor Rzegocki <ajgon@irgon.com> - [GitHub](https://github.com/ajgon/gpg-mailgate)
* Favyen Bastani <fbastani@perennate.com> - [GitHub](https://github.com/uakfdotb/gpg-mailgate)
* Colin Moller <colin@unixarmy.com> - [GitHub](https://github.com/LeftyBC/gpg-mailgate)
* Taylor Hornby <havoc@defuse.ca> - [GitHub](https://github.com/defuse/gpg-mailgate)
* Martin (uragit) <uragit@telemage.com> - [GitHub](https://github.com/uragit/gpg-mailgate)
* Braden Thomas - [BitBucket](https://bitbucket.org/drspringfield/emailencrypt.net/)
* Bruce Markey - [GitHub](https://github.com/TheEd1tor)
* Kiritan Flux [GitHub](https://github.com/kflux)

# To Do

* clean up code
* add optional email registration with attached public key to register@domain.tld
* outsource templates for emails and mailgate-web
* rename from gpg-mailgate to openpgp-s-mime-mailgate or something.....
