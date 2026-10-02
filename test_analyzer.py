import unittest
from analyzer import analyze

class Cases(unittest.TestCase):
    def test_security_behavior(self):
        self.assertEqual(analyze({"Records":[{"eventName":"StopLogging","errorCode":"AccessDenied"}]}), [])
        self.assertEqual(analyze({"Records":[{"eventName":"DeleteTrail"}]})[0]["severity"], "HIGH")

if __name__ == "__main__":
    unittest.main()

