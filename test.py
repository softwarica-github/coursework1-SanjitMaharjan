import unittest
import tkinter as tk
from main import PacketSnifferApp

class TestPacketSnifferApp(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = PacketSnifferApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def testinitialization(self):
        self.assertIsInstance(self.app, PacketSnifferApp)
        self.assertEqual(self.app.running, False)
        self.assertEqual(self.app.packetcounter, 0)

    def teststart_and_stop_sniffing(self):
        self.assertEqual(self.app.running, False)
        self.app.start_sniffing()
        self.assertEqual(self.app.running, True)
        self.app.stop_sniffing()
        self.assertEqual(self.app.running, False)

    def test_clear_screen(self):
        # Add some dummy data to the tree
        self.app.tree.insert("", "end", values=("1", "TCP", "2022-02-27", "192.168.1.1", "192.168.1.2"))
        self.app.clear_screen()
        self.assertEqual(len(self.app.tree.get_children()), 0)


if __name == '__main':
    unittest.main()