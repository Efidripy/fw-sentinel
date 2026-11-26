"""Regression: visually three independent IP columns, not a table of three fields."""
import unittest
import webui
from unittest import mock

import i18n  # noqa: E402

def setUpModule():  # these checks read the Russian texts
    i18n.FORCED = 'ru'


def tearDownModule():
    i18n.FORCED = None


class ThreeColumns(unittest.TestCase):
    def test_three_cards_next_to_each_other(self):
        with mock.patch.object(webui,'path_for',return_value='/events'):
            html=webui.dropped_ip_table([
            ('9.9.9.9',99,'2026-11-25T21:00:00+00:00'),
            ('8.8.8.8',20,'2026-11-25T20:00:00+00:00'),
            ('1.1.1.1',3,'2026-11-25T19:00:00+00:00')])
        self.assertIn('class="blocked-ip-grid"',html)
        self.assertEqual(html.count('class="blocked-ip-card"'),3)
        self.assertNotIn('<table',html)
        self.assertIn('href="/events?ip=9.9.9.9&amp;verdict=drop"',html)
        self.assertEqual(html.count('data-intel-ip='),3)
        self.assertIn('99</strong>',html)
        self.assertIn('2026-11-25 21:00:00',html)
    def test_three_across_css_and_responsive(self):
        self.assertIn('grid-template-columns:repeat(3,minmax(0,1fr))',webui.CSS)
        self.assertIn('grid-template-columns:repeat(2,minmax(0,1fr))',webui.CSS)
        self.assertIn('.blocked-ip-grid{grid-template-columns:minmax(0,1fr)}',webui.CSS)
        self.assertIn("document.getElementById('drop-ip-grid')",webui.DROP_SUMMARY_SCRIPT)
        self.assertIn("card.className='blocked-ip-card'",webui.DROP_SUMMARY_SCRIPT)
        self.assertNotIn("document.createElement('tr')",webui.DROP_SUMMARY_SCRIPT)
    def test_empty_placeholder(self):
        html=webui.dropped_ip_table([])
        self.assertIn('blocked-ip-grid',html)
        self.assertIn('24 часа',html)
