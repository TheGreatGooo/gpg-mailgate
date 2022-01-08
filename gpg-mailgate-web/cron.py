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
import GnuPG
import MySQLdb
import smtplib
import markdown
import syslog
from email.MIMEText import MIMEText
from email.mime.multipart import MIMEMultipart

def appendLog(msg):
	if 'logging' in cfg and 'file' in cfg['logging']:
		if cfg['logging'].get('file') == "syslog":
			syslog.syslog(syslog.LOG_INFO | syslog.LOG_MAIL, msg)
		else:
			logfile = open(cfg['logging']['file'], 'a')
			logfile.write(msg + "\n")
			logfile.close()

def send_msg( mailsubject, messagefile, recipients = None ):
	mailbody = file( cfg['cron']['mail_templates'] + "/" + messagefile).read()
	msg = MIMEMultipart("alternative")

	msg["From"] = cfg['cron']['notification_email']
	msg["To"] = recipients
	msg["Subject"] = mailsubject
	
	msg.attach(MIMEText(mailbody, 'plain'))
	msg.attach(MIMEText(markdown.markdown(mailbody), 'html'))
	
	if 'relay' in cfg and 'host' in cfg['relay'] and 'enc_port' in cfg['relay']:
		relay = (cfg['relay']['host'], int(cfg['relay']['enc_port']))
		smtp = smtplib.SMTP(relay[0], relay[1])
		smtp.sendmail( cfg['cron']['notification_email'], recipients, msg.as_string() )
	else:
		appendLog("Could not send mail due to wrong configuration")

# Read configuration from /etc/gpg-mailgate.conf
_cfg = RawConfigParser()
_cfg.read('/etc/gpg-mailgate.conf')
cfg = dict()
for sect in _cfg.sections():
	cfg[sect] = dict()
	for (name, value) in _cfg.items(sect):
		cfg[sect][name] = value

if 'database' in cfg and 'enabled' in cfg['database'] and cfg['database']['enabled'] == 'yes' and 'name' in cfg['database'] and 'host' in cfg['database'] and 'username' in cfg['database'] and 'password' in cfg['database']:
	connection = MySQLdb.connect(host = cfg['database']['host'], user = cfg['database']['username'], passwd = cfg['database']['password'], db = cfg['database']['name'], port = 3306)
	cursor = connection.cursor()

	# import keys
	cursor.execute("SELECT publickey, id, email FROM gpgmw_keys WHERE status = 0 AND confirm = '' LIMIT 100")
	result_set = cursor.fetchall()

	for row in result_set:
		# delete any other public keys associated with this confirmed email address
		cursor.execute("DELETE FROM gpgmw_keys WHERE email = %s AND id != %s", (row[2], row[1],))
		GnuPG.delete_key(cfg['gpg']['keyhome'], row[2])
		appendLog('Deleted key for <' + row[2] + '> via import request')

		if row[0].strip(): # we have this so that user can submit blank key to remove any encryption
			if GnuPG.confirm_key(row[0], row[2]):
				GnuPG.add_key(cfg['gpg']['keyhome'], row[0]) # import the key to gpg
				cursor.execute("UPDATE gpgmw_keys SET status = 1 WHERE id = %s", (row[1],)) # mark key as accepted
				appendLog('Imported key from <' + row[2] + '>')
				if 'send_email' in cfg['cron'] and cfg['cron']['send_email'] == 'yes':
					send_msg( "PGP key registration successful", "registrationSuccess.md", row[2] )
			else:
				cursor.execute("DELETE FROM gpgmw_keys WHERE id = %s", (row[1],)) # delete key
				appendLog('Import confirmation failed for <' + row[2] + '>')
				if 'send_email' in cfg['cron'] and cfg['cron']['send_email'] == 'yes':
					send_msg( "PGP key registration failed", "registrationError.md", row[2] )
		else:
			# delete key so we don't continue processing it
			cursor.execute("DELETE FROM gpgmw_keys WHERE id = %s", (row[1],))
			if 'send_email' in cfg['cron'] and cfg['cron']['send_email'] == 'yes':
				send_msg( "PGP key deleted", "keyDeleted.md", row[2])

		connection.commit()

	# delete keys
	cursor.execute("SELECT email, id FROM gpgmw_keys WHERE status = 2 LIMIT 100")
	result_set = cursor.fetchall()

	for row in result_set:
		GnuPG.delete_key(cfg['gpg']['keyhome'], row[0])
		cursor.execute("DELETE FROM gpgmw_keys WHERE id = %s", (row[1],))
		appendLog('Deleted key for <' + row[0] + '>')
		connection.commit()
else:
	print("Warning: doing nothing since database settings are not configured!")
