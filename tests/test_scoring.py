import unittest
from detection.scoring import risk_level

class ScoringTests(unittest.TestCase):
    def test_boundaries(self): self.assertEqual([risk_level(x) for x in (0,24,25,49,50,74,75,100)],['LOW','LOW','MEDIUM','MEDIUM','HIGH','HIGH','CRITICAL','CRITICAL'])

if __name__=='__main__': unittest.main()
