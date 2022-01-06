#!/usr/local/bin/python2

import os
import sys

import difflib

import ConfigParser
import logging

from time import sleep

EOL = "\n"

DELAY = 3

RELAY_SCRIPT = "test/relay.py"
CONFIG_FILE = "test/gpg-mailgate.conf"

PYTHON_BIN = "python2.7"

def build_config(config):
    cp = ConfigParser.ConfigParser()

    cp.add_section("logging")
    cp.set("logging", "file", config["log_file"])
    cp.set("logging", "verbose", "yes")

    cp.add_section("gpg")
    cp.set("gpg", "keyhome", config["gpg_keyhome"])

    cp.add_section("smime")
    cp.set("smime", "cert_path", config["smime_certpath"])

    cp.add_section("relay")
    cp.set("relay", "host", "localhost")
    cp.set("relay", "port", config["port"])

    cp.add_section("enc_keymap")
    cp.set("enc_keymap", "alice@disposlab", "1CD245308F0963D038E88357973CF4D9387C44D7")
    cp.set("enc_keymap", "bob@disposlab", "19CF4B47ECC9C47AFA84D4BD96F39FDA0E31BB67")

    logging.debug("Created config with keyhome=%s, cert_path=%s and relay at port %d" %
                  (config["gpg_keyhome"], config["smime_certpath"], config["port"]))
    return cp

def write_test_config(outfile, **config):
    logging.debug("Generating configuration with %s" % repr(config))

    out = open(outfile, "w+")
    cp = build_config(config)
    cp.write(out)
    out.close()

    logging.debug("Wrote configuration to %s" % outfile)

def load_file(name):
	f = open(name, 'r')
	contents = f.read()
	f.close()

	return contents

def strip_eols(strings):
    return map(lambda s: s.strip("\r"), strings)

def compare(result, expected):
    result_lines = strip_eols(result.split(EOL))
    expected_lines = strip_eols(expected.split(EOL))

    return difflib.unified_diff(expected_lines, result_lines,
                                fromfile='expected',
                                tofile='output')

def report_result(message_file, expected, test_output):
    status = None
    if expected in test_output:
        status = "Success"
    else:
        status = "Failure"

    print "%s %s" % (message_file.ljust(30, '.'), status)

def frozen_time_expr(timestamp):
    if timestamp is None:
        return ""
    else:
        return "GPG_FROZEN_TIME=%s" % (timestamp)

def execute_e2e_test(message_file, expected, **kwargs):
    test_command = "GPG_MAILGATE_CONFIG=%s %s gpg-mailgate.py %s < %s" % (
        kwargs["config_path"],
        PYTHON_BIN,
        kwargs["to_addr"],
        message_file)
    result_command = "%s %s %d" % (PYTHON_BIN, RELAY_SCRIPT, kwargs["port"])

    logging.debug("Spawning: '%s'" % (result_command))
    pipe = os.popen(result_command, 'r')

    logging.debug("Spawning: '%s'" % (test_command))
    msgin = os.popen(test_command, 'w')
    msgin.write(load_file(message_file))
    msgin.close()

    testout = pipe.read()
    pipe.close()

    logging.debug("Read %d characters of test output: '%s'" % (len(testout), testout))

    report_result(message_file, expected, testout)

def load_test_config():
    cp = ConfigParser.ConfigParser()
    cp.read("test/e2e.ini")

    return cp


config = load_test_config()

logging.basicConfig(filename	= "test/logs/e2e.log",
                    format		= "%(asctime)s %(pathname)s:%(lineno)d %(levelname)s [%(funcName)s] %(message)s",
                    datefmt		= "%Y-%m-%d %H:%M:%S",
                    level		= logging.DEBUG)

config_path = os.getcwd() + "/" + CONFIG_FILE

write_test_config(config_path,
                  port				= config.getint("relay", "port"),
                  gpg_keyhome		= "test/keyhome",
                  smime_certpath	= "test/certs",
                  log_file			= "test/logs/gpg-mailgate.log")

for case_no in range(1, config.getint("tests", "cases")+1):
    case_name = "case-%d" % (case_no)
    print "Executing: %s" % (config.get(case_name, "descr"))

    execute_e2e_test(config.get(case_name, "in"),
                     config.get(case_name, "out"),
                     config_path	= config_path,
                     to_addr		= config.get(case_name, "to"),
                     port			= config.getint("relay", "port"))

    # sleep(DELAY)
