import GnuPG

import unittest

class GnuPGUtilitiesTest(unittest.TestCase):
	def test_build_default_command(self):
		cmd = GnuPG.build_command("test/keyhome")
		self.assertEqual(cmd, ["gpg", "--homedir", "test/keyhome"])

	def test_build_command_extended_with_args(self):
		cmd = GnuPG.build_command("test/keyhome", "--foo", "--bar")
		self.assertEqual(cmd, ["gpg", "--homedir", "test/keyhome", "--foo", "--bar"])


if __name__ == '__main__':
	unittest.main()
