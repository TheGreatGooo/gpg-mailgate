#!/usr/bin/python

from configparser import RawConfigParser
import email, os, smtplib, sys, traceback, markdown, syslog, requests
from M2Crypto import BIO, Rand, SMIME, X509

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read('/etc/gpg-mailgate.conf')
cfg = dict()
for sect in _cfg.sections():
	cfg[sect] = dict()
	for (name, value) in _cfg.items(sect):
		cfg[sect][name] = value

def log(msg):
	if 'logging' in cfg and 'file' in cfg['logging']:
		if cfg['logging']['file'] == "syslog":
			syslog.syslog(syslog.LOG_INFO | syslog.LOG_MAIL, msg)
		else:
			logfile = open(cfg['logging']['file'], 'a')
			logfile.write(msg + "\n")
			logfile.close()

CERT_PATH = cfg['smime']['cert_path']+"/"

def send_msg( message, from_addr, recipients = None ):
    
	if 'relay' in cfg and 'host' in cfg['relay'] and 'enc_port' in cfg['relay']:
		relay = (cfg['relay']['host'], int(cfg['relay']['enc_port']))
		smtp = smtplib.SMTP(relay[0], relay[1])
		smtp.sendmail( from_addr, recipients, message.as_string() )
	else:
		log("Could not send mail due to wrong configuration")

if __name__ == "__main__":
#	try:
		# Read e-mail from stdin
		raw = sys.stdin.read()
		register_msg = email.message_from_string( raw )
		from_addr = email.utils.parseaddr(register_msg['From'])[1]

		sign_part = None
		for msg_part in register_msg.walk():
			if msg_part.get_content_type().lower() == "application/pkcs7-signature" or msg_part.get_content_type().lower() == "application/x-pkcs7-signature":
				sign_type = 'smime'
				sign_part = msg_part
				break
			# This may cause that a non ASCII-armored key will be seen as valid. Other solution is not that efficient though
			#elif msg_part.get_content_type().lower() == "application/pgp-keys":
			#	sign_type = 'pgp'
			#	sign_part = msg_part.get_payload()
			#	break
			elif "-----BEGIN PGP PUBLIC KEY BLOCK-----" in msg_part.get_payload() and "-----END PGP PUBLIC KEY BLOCK-----" in msg_part.get_payload():
				msg_content = msg_part.get_payload()
				start = msg_content.find("-----BEGIN PGP PUBLIC KEY BLOCK-----")
				end = msg_content.find("-----END PGP PUBLIC KEY BLOCK-----")
				sign_type = 'pgp'
				sign_part = msg_content[start:end + 34]
				break

		if sign_part == None:
			log("Unable to find PKCS7 signature or public PGP key in registration email")

			failure_msg = file( cfg['mailregister']['mail_templates'] + "/registrationError.md").read()
			msg = MIMEMultipart("alternative")
			msg["From"] = cfg['mailregister']['register_email']
			msg["To"] = from_addr
			msg["Subject"] = "S/MIME / OpenPGP registration failed"

			msg.attach(MIMEText(failure_msg, 'plain'))
			msg.attach(MIMEText(markdown.markdown(failure_msg), 'html'))

			send_msg(msg, cfg['mailregister']['register_email'], [from_addr])
			sys.exit(0)
		
		if sign_type == 'smime':
			raw_sig = sign_part.get_payload().replace("\n", "")
			# re-wrap signature so that it fits base64 standards
			cooked_sig = '\n'.join(raw_sig[pos:pos+76] for pos in range(0, len(raw_sig), 76))
			
			# now, wrap the signature in a PKCS7 block
			sig = """
-----BEGIN PKCS7-----
%s
-----END PKCS7-----
		""" % cooked_sig

			# and load it into an SMIME p7 object through the BIO I/O buffer:
			buf = BIO.MemoryBuffer(sig)
			p7 = SMIME.load_pkcs7_bio(buf)

			sk = X509.X509_Stack()
			signers = p7.get0_signers(sk)
			signing_cert = signers[0]

			#Save certificate compatible to RFC 2821
			splitted_from_addr = from_addr.split('@')
			processed_from_addr = splitted_from_addr[0] + '@' + splitted_from_addr[1].lower()

			signing_cert.save(os.path.join(CERT_PATH, processed_from_addr))
					
			# format in user-specific data
			# sending success mail only for S/MIME as GPGMW handles this on its own
			success_msg = file(cfg['mailregister']['mail_templates']+"/registrationSuccess.md").read()
			success_msg = success_msg.replace("[:FROMADDRESS:]", from_addr)
			
			msg = MIMEMultipart("alternative")
			msg["From"] = cfg['mailregister']['register_email']
			msg["To"] = from_addr
			msg["Subject"] = "S/MIME certificate registration succeeded"

			msg.attach(MIMEText(success_msg, 'plain'))
			msg.attach(MIMEText(markdown.markdown(success_msg), 'html'))
			
			send_msg(msg, cfg['mailregister']['register_email'], [from_addr])
			
			log("S/MIME Registration succeeded")
		elif sign_type == 'pgp':
			# send POST to gpg-mailgate webpanel
			sig = sign_part
			payload = {'email': from_addr, 'key': sig}
			r = requests.post(cfg['mailregister']['webpanel_url'], data=payload)

			if r.status_code != 200:
				log("Could not hand registration over to GPGMW. Error: %s" % r.status_code)
				error_msg = file(cfg['mailregister']['mail_templates']+"/gpgmwFailed.md").read()
				error_msg = error_msg.replace("[:FROMADDRESS:]", from_addr)
			
				msg = MIMEMultipart("alternative")
				msg["From"] = cfg['mailregister']['register_email']
				msg["To"] = from_addr
				msg["Subject"] = "PGP key registration failed"

				msg.attach(MIMEText(error_msg, 'plain'))
				msg.attach(MIMEText(markdown.markdown(error_msg), 'html'))
			
				send_msg(msg, cfg['mailregister']['register_email'], [from_addr])
			else:
				log("PGP registration is handed over to GPGMW")
#	except:
#		log("Registration exception")
#		sys.exit(0)
