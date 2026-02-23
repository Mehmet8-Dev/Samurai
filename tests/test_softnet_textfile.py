import unittest


class TestSoftnetTextfile(unittest.TestCase):
    def test_softnet_parser_smoke(self):
        from monitoring.bin.collect_softnet_textfile import _sum_fields

        rows = [
            [10, 1, 2, 3],
            [20, 0, 1, 0],
            [5],
        ]
        s = _sum_fields(rows)
        self.assertEqual(s["processed"], 35)
        self.assertEqual(s["dropped"], 1)
        self.assertEqual(s["time_squeeze"], 3)
        self.assertEqual(s["cpu_collision"], 3)

