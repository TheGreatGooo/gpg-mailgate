#!/usr/bin/python

#
#	gpg-mailgate
#
#	This file is part of the gpg-mailgate source code.
#
#	gpg-mailgate is free software: you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation, either version 3 of the License, or
#	(at your option) any later version.
#
#	gpg-mailgate source code is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with gpg-mailgate source code. If not, see <http://www.gnu.org/licenses/>.
#

from configparser import RawConfigParser
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
import copy
import email
import email.message
import email.utils
import GnuPG
import os
import re
import smtplib
import sys
import syslog
import traceback


# imports for S/MIME
from M2Crypto import BIO, Rand, SMIME, X509
from email.mime.message import MIMEMessage

# Environment variable name we read to retrieve configuration path.  This is to
# enable non-root users to set up and run GPG Mailgate and to make the software
# testable.
CONFIG_PATH_ENV = "GPG_MAILGATE_CONFIG"

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read(os.getenv(CONFIG_PATH_ENV, '/etc/gpg-mailgate.conf'))
cfg = dict()
for sect in _cfg.sections():
	cfg[sect] = dict()
	for (name, value) in _cfg.items(sect):
		cfg[sect][name] = value

def log( msg ):
	if 'logging' in cfg and 'file' in cfg['logging']:
		if cfg['logging'].get('file') == "syslog":
			syslog.syslog(syslog.LOG_INFO | syslog.LOG_MAIL, msg)
		else:
			logfile = open(cfg['logging']['file'], 'a')
			logfile.write(msg + "\n")
			logfile.close()

verbose = 'logging' in cfg and 'verbose' in cfg['logging'] and cfg['logging'].get('verbose') == 'yes'

# Read e-mail from stdin
raw = sys.stdin.read()
raw_message = email.message_from_string( raw )
from_addr = raw_message['From']
to_addrs = sys.argv[1:]

def gpg_decrypt( raw_message, recipients ):

	gpg_to = list()
	ungpg_to = list()

	# This is needed to avoid encryption if decryption is set to keymap only,
	# private key is present but not in keymap.
	noenc_to = list()

	if not get_bool_from_cfg('gpg', 'keyhome'):
		log("No valid entry for gpg keyhome. Decryption aborted.")
		return recipients

	keys = GnuPG.private_keys( cfg['gpg']['keyhome'] )

	if get_bool_from_cfg('default', 'dec_regex'):
		dec_regex = cfg['default']['dec_regex']
	else:
		dec_regex = None

	for fingerprint in keys:
		keys[fingerprint] = sanitize_case_sense(keys[fingerprint])

	for to in recipients:
		if to in keys.values() and not get_bool_from_cfg('default', 'dec_keymap_only', 'yes'):
			gpg_to.append(to)
		# Is this recipient defined in regex for default decryption?
		elif not (dec_regex is None) and not (re.match(dec_regex, to) is None):
			log("Using default decrytion defined in dec_regex for recipient '%s'" % to)
			gpg_to.append(to)
		elif get_bool_from_cfg('dec_keymap', to):
			log("Decrypt keymap has key '%s'" % cfg['dec_keymap'][to] )
			# Check we've got a matching key! If not, decline to attempt decryption. The key is checked for safty reasons.
			if not cfg['dec_keymap'][to] in keys:
				log("Key '%s' in decryption keymap not found in keyring for email address '%s'. Won't decrypt." % (cfg['dec_keymap'][to], to))
				# Avoid unwanted encryption if set
				if to in keys.values() and get_bool_from_cfg('default', 'failsave_dec', 'yes'):
					noenc_to.append(to)
				else:
					ungpg_to.append(to)
			else:
				gpg_to.append(to)
		else:
			if verbose:
				log("Recipient (%s) not in PGP domain list for decrypting." % to)
			# Avoid unwanted encryption if set
			if to in keys.values() and get_bool_from_cfg('default', 'failsave_dec', 'yes'):
				noenc_to.append(to)
			else:
				ungpg_to.append(to)

	if gpg_to != list():
		send_msg( gpg_decrypt_all_payloads( raw_message ).as_string(), gpg_to )

	if noenc_to != list():
		log("Do not try to encrypt mails for: %s" % ', '.join( noenc_to ))
		send_msg(raw_message.as_string(), noenc_to)

	return ungpg_to

def gpg_decrypt_all_payloads( message ):

	# We don't want to modify the original message
	decrypted_message = copy.deepcopy(message)

	# Check if message is PGP/MIME encrypted
	if not (message.get_param('protocol') is None) and message.get_param('protocol') == 'application/pgp-encrypted' and message.is_multipart():
		decrypted_message = decrypt_mime(decrypted_message)

	# At this point the message could only be PGP/INLINE encrypted, unencrypted or
	# encrypted with a mechanism not covered by GPG-Mailgate
	elif get_bool_from_cfg('default', 'no_inline_dec', 'no'):
		# Check if message is PGP/INLINE encrypted and has attachments (or unencrypted with attachments)
		if message.is_multipart():

			# Set message's payload to list so payloads can be attached later on
			decrypted_message.set_payload(list())

			# We only need to hand over the original message here. Not needed for other decrypt implementations.
			decrypted_message, success = decrypt_inline_with_attachments(message, False, decrypted_message)

			# Add header here to avoid it being appended several times
			if get_bool_from_cfg('default', 'add_header', 'yes') and success:
				decrypted_message['X-GPG-Mailgate'] = 'Decrypted by GPG Mailgate'

		# Check if message is PGP/INLINE encrypted without attachments (or unencrypted without attachments)
		else:
			decrypted_message = decrypt_inline_without_attachments(decrypted_message)

	return decrypted_message

def decrypt_mime( decrypted_message ):
	# Please note: Signatures will disappear while decrypting and will not be checked

	# Getting the part which should be PGP encrypted (according to RFC)
	msg_content = decrypted_message.get_payload(1).get_payload()

	if "-----BEGIN PGP MESSAGE-----" in msg_content and "-----END PGP MESSAGE-----" in msg_content:
		start = msg_content.find("-----BEGIN PGP MESSAGE-----")
		end = msg_content.find("-----END PGP MESSAGE-----")
		decrypted_payload, decrypt_success = decrypt_payload(msg_content[start:end + 25])
		
		if decrypt_success:
			# Making decrypted_message a "normal" unencrypted message
			decrypted_message.del_param('protocol')
			decrypted_message.set_type(decrypted_payload.get_content_type())

			# Restore Content-Disposition header from original message
			if not (decrypted_payload.get('Content-Disposition') is None):
				if not (decrypted_message.get('Content-Disposition') is None):
					decrypted_message.replace_header('Content-Disposition', decrypted_payload.get('Content-Disposition'))
				else:
					decrypted_message.set_param(decrypted_payload.get('Content-Disposition'), "", 'Content-Disposition')

			if decrypted_payload.is_multipart():
				# Clear message's original payload and insert the decrypted payloads
				decrypted_message.set_payload(list())
				decrypted_message = generate_message_from_payloads( decrypted_payload, decrypted_message )
				decrypted_message.preamble = "This is a multi-part message in MIME format"
			else:
				decrypted_message.set_payload(decrypted_payload.get_payload())
				decrypted_message.preamble = None


			if get_bool_from_cfg('default', 'add_header', 'yes'):
				decrypted_message['X-GPG-Mailgate'] = 'Decrypted by GPG Mailgate'

	# If decryption fails, decrypted_message is equal to the original message
	return decrypted_message

def decrypt_inline_with_attachments( payloads, success, message = None ):
	
	if message is None:
		message = email.mime.multipart.MIMEMultipart(payloads.get_content_subtype())

	for payload in payloads.get_payload():
		if( isinstance(payload.get_payload(), list) ):
			# Take care of cascaded MIME messages
			submessage, subsuccess = decrypt_inline_with_attachments( payload, success )
			message.attach(submessage)
			success = success or subsuccess
		else:
			msg_content = payload.get_payload()

			# Getting values for different implementations as PGP/INLINE is not implemented
			# the same on different clients
			pgp_inline_tags = "-----BEGIN PGP MESSAGE-----" in msg_content and "-----END PGP MESSAGE-----" in msg_content
			attachment_filename = payload.get_filename() 

			if pgp_inline_tags or not (attachment_filename is None) and not (re.search('.\.pgp$', attachment_filename) is None):
				if pgp_inline_tags:
					start = msg_content.find("-----BEGIN PGP MESSAGE-----")
					end = msg_content.find("-----END PGP MESSAGE-----")
					decrypted_payload, decrypt_success = decrypt_payload(msg_content[start:end + 25])
				# Some implementations like Enigmail have strange interpretations of PGP/INLINE
				# This tries to cope with it as good as possible.
				else:
					build_message = """
-----BEGIN PGP MESSAGE-----

%s
-----END PGP MESSAGE-----""" % msg_content

					decrypted_payload, decrypt_success = decrypt_payload(build_message)
				
				# Was at least one decryption successful?
				success = success or decrypt_success
				
				if decrypt_success:

					if not (attachment_filename is None):
						attachment_filename = re.sub('\.pgp$', '', attachment_filename)
						payload.set_param('filename', attachment_filename, 'Content-Disposition')
						payload.set_param('name', attachment_filename, 'Content-Type')
					# Need this nasty hack to avoid double blank lines at beginning of message
					payload.set_payload(decrypted_payload.as_string()[1:])

					message.attach(payload)
				else:
					# Message could not be decrypted, so non-decrypted message is attached
					message.attach(payload)
			else:
				# There was no encrypted payload found, so the original payload is attached
				message.attach(payload)

	return message, success

def decrypt_inline_without_attachments( decrypted_message ):

	msg_content = decrypted_message.get_payload()
	if "-----BEGIN PGP MESSAGE-----" in msg_content and "-----END PGP MESSAGE-----" in msg_content:
		start = msg_content.find("-----BEGIN PGP MESSAGE-----")
		end = msg_content.find("-----END PGP MESSAGE-----") 
		decrypted_payload, decrypt_success = decrypt_payload(msg_content[start:end + 25])

		if decrypt_success:
			# Need this nasty hack to avoid double blank lines at beginning of message
			decrypted_message.set_payload(decrypted_payload.as_string()[1:])

			if get_bool_from_cfg('default', 'add_header', 'yes'):
				decrypted_message['X-GPG-Mailgate'] = 'Decrypted by GPG Mailgate'
	
	# If message was not encrypted, this will just return the original message
	return decrypted_message

def decrypt_payload( payload ):

	gpg = GnuPG.GPGDecryptor( cfg['gpg']['keyhome'] )
	gpg.update( payload )
	decrypted_data, returncode = gpg.decrypt()
	if verbose:
		log("Return code from decryption=%d (0 indicates success)." % returncode)
	if returncode != 0:
		log("Decrytion failed with return code %d. Decryption aborted." % returncode)
		return payload, False

	# Decryption always generate a new message
	decrypted_msg = email.message_from_string(decrypted_data)

	return decrypted_msg, True

def gpg_encrypt( raw_message, recipients ):

	if not get_bool_from_cfg('gpg', 'keyhome'):
		log("No valid entry for gpg keyhome. Encryption aborted.")
		return recipients

	keys = GnuPG.public_keys( cfg['gpg']['keyhome'] )
	for fingerprint in keys:
		keys[fingerprint] = sanitize_case_sense(keys[fingerprint])

	gpg_to = list()
	ungpg_to = list()

	for to in recipients:

		# Check if recipient is in keymap
		if get_bool_from_cfg('enc_keymap', to):
			log("Encrypt keymap has key '%s'" % cfg['enc_keymap'][to] )
			# Check we've got a matching key!
			if cfg['enc_keymap'][to] in keys:
				gpg_to.append( (to, cfg['enc_keymap'][to]) )
				continue
			else:
				log("Key '%s' in encrypt keymap not found in keyring for email address '%s'." % (cfg['enc_keymap'][to], to))

		# Check if key in keychain is present
		if to in keys.values() and not get_bool_from_cfg('default', 'enc_keymap_only', 'yes'):
			gpg_to.append( (to, to) )
			continue

		# Check if there is a default key for the domain
		splitted_to = to.split('@')
		if len(splitted_to) > 1:
			domain = splitted_to[1]
			if get_bool_from_cfg('enc_domain_keymap', domain):
				log("Encrypt domain keymap has key '%s'" % cfg['enc_dec_keymap'][domain] )
				# Check we've got a matching key!
				if cfg['enc_domain_keymap'][domain] in keys:
					log("Using default domain key for recipient '%s'" % to)
					gpg_to.append( (to, cfg['enc_domain_keymap'][domain]) )
					continue
				else:
					log("Key '%s' in encrypt domain keymap not found in keyring for email address '%s'." % (cfg['enc_domain_keymap'][domain], to))
		
		# At this point no key has been found
		if verbose:
			log("Recipient (%s) not in PGP domain list for encrypting." % to)
		ungpg_to.append(to)

	if gpg_to != list():
		log("Encrypting email to: %s" % ' '.join( x[0] for x in gpg_to ))

		# Getting PGP style for recipient
		gpg_to_smtp_mime = list()
		gpg_to_cmdline_mime = list()

		gpg_to_smtp_inline = list()
		gpg_to_cmdline_inline = list()

		for rcpt in gpg_to:
			# Checking pre defined styles in settings first
			if get_bool_from_cfg('pgp_style', rcpt[0], 'mime'):
				gpg_to_smtp_mime.append(rcpt[0])
				gpg_to_cmdline_mime.extend(rcpt[1].split(','))
			elif get_bool_from_cfg('pgp_style', rcpt[0], 'inline'):
				gpg_to_smtp_inline.append(rcpt[0])
				gpg_to_cmdline_inline.extend(rcpt[1].split(','))
			else:
				# Log message only if an unknown style is defined
				if get_bool_from_cfg('pgp_style', rcpt[0]):
					log("Style %s for recipient %s is not known. Use default as fallback." % (cfg['pgp_style'][rcpt[0]], rcpt[0]))

				# If no style is in settings defined for recipient, use default from settings
				if get_bool_from_cfg('default', 'mime_conversion', 'yes'):
					gpg_to_smtp_mime.append(rcpt[0])
					gpg_to_cmdline_mime.extend(rcpt[1].split(','))
				else:
					gpg_to_smtp_inline.append(rcpt[0])
					gpg_to_cmdline_inline.extend(rcpt[1].split(','))

		if gpg_to_smtp_mime != list():
			# Encrypt mail with PGP/MIME
			raw_message_mime = copy.deepcopy(raw_message)

			if get_bool_from_cfg('default', 'add_header', 'yes'):
				raw_message_mime['X-GPG-Mailgate'] = 'Encrypted by GPG Mailgate'

			if 'Content-Transfer-Encoding' in raw_message_mime:
				raw_message_mime.replace_header('Content-Transfer-Encoding', '8BIT')
			else:
				raw_message_mime['Content-Transfer-Encoding'] = '8BIT'

			encrypted_payloads = encrypt_all_payloads_mime( raw_message_mime, gpg_to_cmdline_mime )
			raw_message_mime.set_payload( encrypted_payloads )

			send_msg( raw_message_mime.as_string(), gpg_to_smtp_mime )

		if gpg_to_smtp_inline != list():
			# Encrypt mail with PGP/INLINE
			raw_message_inline = copy.deepcopy(raw_message)

			if get_bool_from_cfg('default', 'add_header', 'yes'):
				raw_message_inline['X-GPG-Mailgate'] = 'Encrypted by GPG Mailgate'

			if 'Content-Transfer-Encoding' in raw_message_inline:
				raw_message_inline.replace_header('Content-Transfer-Encoding', '8BIT')
			else:
				raw_message_inline['Content-Transfer-Encoding'] = '8BIT'

			encrypted_payloads = encrypt_all_payloads_inline( raw_message_inline, gpg_to_cmdline_inline )
			raw_message_inline.set_payload( encrypted_payloads )

			send_msg( raw_message_inline.as_string(), gpg_to_smtp_inline )

	return ungpg_to

def encrypt_all_payloads_inline( message, gpg_to_cmdline ):

	# This breaks cascaded MIME messages. Blame PGP/INLINE.
	encrypted_payloads = list()
	if isinstance(message.get_payload(), str):
		return encrypt_payload( message, gpg_to_cmdline ).get_payload()

	for payload in message.get_payload():
		if( isinstance(payload.get_payload(), list) ):
			encrypted_payloads.extend( encrypt_all_payloads_inline( payload, gpg_to_cmdline ) )
		else:
			encrypted_payloads.append( encrypt_payload( payload, gpg_to_cmdline ) )

	return encrypted_payloads

def encrypt_all_payloads_mime( message, gpg_to_cmdline ):

	# Convert a plain text email into PGP/MIME attachment style.  Modeled after enigmail.
	submsg1 = email.message.Message()
	submsg1.set_payload("Version: 1\n")
	submsg1.set_type("application/pgp-encrypted")
	submsg1.set_param('PGP/MIME version identification', "", 'Content-Description' )

	submsg2 = email.message.Message()
	submsg2.set_type("application/octet-stream")
	submsg2.set_param('name', "encrypted.asc")
	submsg2.set_param('OpenPGP encrypted message', "", 'Content-Description' )
	submsg2.set_param('inline', "",                'Content-Disposition' )
	submsg2.set_param('filename', "encrypted.asc", 'Content-Disposition' )

	if isinstance(message.get_payload(), str):
		# WTF!  It seems to swallow the first line.  Not sure why.  Perhaps
		# it's skipping an imaginary blank line someplace. (ie skipping a header)
		# Workaround it here by prepending a blank line.
		# This happens only on text only messages.
		additionalSubHeader=""
		if 'Content-Type' in message and not message['Content-Type'].startswith('multipart'):
			additionalSubHeader="Content-Type: "+message['Content-Type']+"\n"
		submsg2.set_payload(additionalSubHeader+"\n" +message.get_payload(decode=True))
		check_nested = True
	else:
		processed_payloads = generate_message_from_payloads(message)
		submsg2.set_payload(processed_payloads.as_string())
		check_nested = False

	message.preamble = "This is an OpenPGP/MIME encrypted message (RFC 2440 and 3156)"

	# Use this just to generate a MIME boundary string.
	junk_msg = MIMEMultipart()
	junk_str = junk_msg.as_string()  # WTF!  Without this, get_boundary() will return 'None'!
	boundary = junk_msg.get_boundary()

    # This also modifies the boundary in the body of the message, ie it gets parsed.
	if 'Content-Type' in message:
		message.replace_header('Content-Type', "multipart/encrypted; protocol=\"application/pgp-encrypted\";\nboundary=\"%s\"\n" % boundary)
	else:
		message['Content-Type'] = "multipart/encrypted; protocol=\"application/pgp-encrypted\";\nboundary=\"%s\"\n" % boundary

	return [ submsg1, encrypt_payload(submsg2, gpg_to_cmdline, check_nested) ]

def encrypt_payload( payload, gpg_to_cmdline, check_nested = True ):

	raw_payload = payload.get_payload(decode=True)
	if check_nested and b"-----BEGIN PGP MESSAGE-----" in raw_payload and b"-----END PGP MESSAGE-----" in raw_payload:
		if verbose:
			log("Message is already pgp encrypted. No nested encryption needed.")
		return payload

	# No check is needed for cfg['gpg']['keyhome'] as this is already done in method gpg_encrypt
	gpg = GnuPG.GPGEncryptor( cfg['gpg']['keyhome'], gpg_to_cmdline, payload.get_content_charset() )
	gpg.update( raw_payload )
	encrypted_data, returncode = gpg.encrypt()
	if verbose:
		log("Return code from encryption=%d (0 indicates success)." % returncode)
	if returncode != 0:
		log("Encrytion failed with return code %d. Encryption aborted." % returncode)
		return payload

	payload.set_payload( encrypted_data )
	isAttachment = payload.get_param( 'attachment', None, 'Content-Disposition' ) is not None

	if isAttachment:
		filename = payload.get_filename()
		if filename:
			pgpFilename = filename + ".pgp"
			if not (payload.get('Content-Disposition') is None):
				payload.set_param( 'filename', pgpFilename, 'Content-Disposition' )
			if not (payload.get('Content-Type') is None) and not (payload.get_param( 'name' ) is None):
				payload.set_param( 'name', pgpFilename )
	if not (payload.get('Content-Transfer-Encoding') is None):
		payload.replace_header( 'Content-Transfer-Encoding', "7bit" )

	return payload

def smime_encrypt( raw_message, recipients ):
	
	if not get_bool_from_cfg('smime', 'cert_path'):
		log("No valid path for S/MIME certs found in config file. S/MIME encryption aborted.")
		return recipients

	cert_path = cfg['smime']['cert_path']+"/"
	s = SMIME.SMIME()
	sk = X509.X509_Stack()
	smime_to = list()
	unsmime_to = list()

	for addr in recipients:
		cert_and_email = get_cert_for_email(addr, cert_path)

		if not (cert_and_email is None):
			(to_cert, normal_email) = cert_and_email
			if verbose:
				log("Found cert " + to_cert + " for " + addr + ": " + normal_email)
			smime_to.append(addr)
			x509 = X509.load_cert(to_cert, format=X509.FORMAT_PEM)
			sk.push(x509)
		else:
			unsmime_to.append(addr)

	if smime_to != list():
		s.set_x509_stack(sk)
		s.set_cipher(SMIME.Cipher('aes_192_cbc'))
		p7 = s.encrypt( BIO.MemoryBuffer( raw_message.as_string() ) )
		# Output p7 in mail-friendly format.
		out = BIO.MemoryBuffer()
		out.write('From: ' + from_addr + '\n')
		out.write('To: ' + raw_message['To'] + '\n')
		if raw_message['Cc']:
			out.write('Cc: ' + raw_message['Cc'] + '\n')
		if raw_message['Bcc']:
			out.write('Bcc: ' + raw_message['Bcc'] + '\n')
		if raw_message['Subject']:
			out.write('Subject: '+ raw_message['Subject'] + '\n')

		if get_bool_from_cfg('default', 'add_header', 'yes'):
			out.write('X-GPG-Mailgate: Encrypted by GPG Mailgate\n')

		s.write(out, p7)

		if verbose:
			log("Sending message from " + from_addr + " to " + str(smime_to))

		send_msg(out.read(), smime_to)
	if unsmime_to != list():
		if verbose:
			log("Unable to find valid S/MIME certificates for " + str(unsmime_to))

	return unsmime_to

def get_cert_for_email( to_addr, cert_path ):

	files_in_directory = os.listdir(cert_path)
	for filename in files_in_directory:
		file_path = os.path.join(cert_path, filename)
		if not os.path.isfile(file_path):
			continue

		if get_bool_from_cfg('default', 'mail_case_insensitive', 'yes'):
			if filename.lower() == to_addr:
				return (file_path, to_addr)
		else:
			if filename == to_addr:
				return (file_path, to_addr)
	# support foo+ignore@bar.com -> foo@bar.com
	multi_email = re.match('^([^\+]+)\+([^@]+)@(.*)$', to_addr)
	if multi_email:
		fixed_up_email = "%s@%s" % (multi_email.group(1), multi_email.group(3))
		if verbose:
			log("Multi-email %s converted to %s" % (to_addr, fixed_up_email))
		return get_cert_for_email(fixed_up_email)

	return None

def get_bool_from_cfg( section, key = None, evaluation = None ):

	if not (key is None) and not (evaluation is None):
		return section in cfg and cfg[section].get(key) == evaluation

	elif not (key is None) and (evaluation is None):
		return section in cfg and not (cfg[section].get(key) is None)

	else:
		return section in cfg

def sanitize_case_sense( address ):

	if get_bool_from_cfg('default', 'mail_case_insensitive', 'yes'):
		address = address.lower()
	else:
		if isinstance(address, str):
			sep = '@'
		else:
			sep = b'@'
		splitted_address = address.split(sep)
		if len(splitted_address) > 1:
			address = splitted_address[0] + sep + splitted_address[1].lower()

	return address

def generate_message_from_payloads( payloads, message = None ):

	if message == None:
		message = email.mime.multipart.MIMEMultipart(payloads.get_content_subtype())

	for payload in payloads.get_payload():
		if( isinstance(payload.get_payload(), list) ):
			message.attach(generate_message_from_payloads(payload))
		else:
			message.attach(payload)

	return message

def get_first_payload( payloads ):

	if payloads.is_multipart():
		return get_first_payload(payloads.get_payload(0))
	else:
		return payloads

def send_msg( message, recipients ):

	recipients = [_f for _f in recipients if _f]
	if recipients:
		if not (get_bool_from_cfg('relay', 'host') and get_bool_from_cfg('relay', 'port')):
			log("Missing settings for relay. Sending email aborted.")
			return None
		log("Sending email to: <%s>" % '> <'.join( recipients ))
		relay = (cfg['relay']['host'], int(cfg['relay']['port']))
		smtp = smtplib.SMTP(relay[0], relay[1])
		if 'relay' in cfg and 'starttls' in cfg['relay'] and cfg['relay']['starttls'] == 'yes':
			smtp.starttls()
		smtp.sendmail( from_addr, recipients, message )
	else:
		log("No recipient found")

def sort_recipients( raw_message, from_addr, to_addrs ):

	recipients_left = list()
	for recipient in to_addrs:
		recipients_left.append(sanitize_case_sense(recipient))

	# Decrypt mails for recipients with known private PGP keys 
	recipients_left = gpg_decrypt(raw_message, recipients_left)
	if recipients_left == list():
		return

	# There is no need for nested encryption
	first_payload = get_first_payload(raw_message)
	if first_payload.get_content_type() == 'application/pkcs7-mime':
		if verbose:
			log("Message is already encrypted with S/MIME. Encryption aborted.")
		send_msg(raw_message.as_string(), recipients_left)
		return

	first_payload = first_payload.get_payload(decode=True)
	if b"-----BEGIN PGP MESSAGE-----" in first_payload and b"-----END PGP MESSAGE-----" in first_payload:
		if verbose:
			log("Message is already encrypted as PGP/INLINE. Encryption aborted.")
		send_msg(raw_message.as_string(), recipients_left)
		return

	if raw_message.get_content_type() == 'multipart/encrypted':
		if verbose:
			log("Message is already encrypted. Encryption aborted.")
		send_msg(raw_message.as_string(), recipients_left)
		return

	# Encrypt mails for recipients with known public PGP keys
	recipients_left = gpg_encrypt(raw_message, recipients_left)
	if recipients_left == list():
		return

	# Encrypt mails for recipients with known S/MIME certificate
	recipients_left = smime_encrypt(raw_message, recipients_left)
	if recipients_left == list():
		return

	# Send out mail to recipients which are left
	send_msg(raw_message.as_string(), recipients_left)


# Let's start
sort_recipients(raw_message, from_addr, to_addrs)
