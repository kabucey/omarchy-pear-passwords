"""A partial CloudKit snapshot must never become a successful local vault sync."""

import base64
import copy
import plistlib
import unittest
from unittest.mock import patch

from icp.errors import AppleError
from icp.daemon import apple
from icp.keychain import crypto, pipeline
from icp.octagon import client as octagon
from icp.transport.ckks import CloudKitRecord

from apple_fakes import FakeStore
from test_apple_ctx import JOINED, _ctx


class SyncIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tlk, self.class_key, self.item_key = b't' * 64, b'c' * 64, b'i' * 64
        self.key = CloudKitRecord('class', 'synckey', {
            'parentkeyref': 'tlk',
            'wrappedkey': base64.b64encode(crypto.siv_wrap(self.tlk, self.class_key)).decode()})
        self.item = CloudKitRecord('item', 'item', {
            'parentkeyref': 'class',
            'wrappedkey': base64.b64encode(crypto.siv_wrap(self.class_key, self.item_key)).decode()})
        aad = pipeline.authenticated_data_v2('item', self.item.fields,
                                              encver=2, gen=0, parent_key_id='class')
        self.item.fields['data'] = crypto.encrypt_item(self.item_key, plistlib.dumps({
            'class': 'inet', 'agrp': 'com.apple.cfnetwork', 'srvr': 'example.com',
            'acct': 'alex', 'v_Data': b'password'}), aad, iv=b'v' * 16)

    def test_incomplete_decryption_never_applies_a_snapshot_or_marks_it_synced(self):
        # Exercise the real crypto pipeline through the daemon's sync boundary; only
        # Apple's network fetch and peer identity are replaced with offline fixtures.
        for failure in ('missing-class-key', 'missing-data', 'bad-auth-tag', 'bad-plist'):
            with self.subTest(failure=failure):
                bad = copy.deepcopy(self.item)
                bad.record_name = 'bad-item'
                if failure == 'missing-class-key':
                    bad.fields['parentkeyref'] = 'missing'
                elif failure == 'missing-data':
                    bad.fields.pop('data')
                elif failure == 'bad-plist':
                    aad = pipeline.authenticated_data_v2('bad-item', bad.fields,
                                                          encver=2, gen=0, parent_key_id='class')
                    bad.fields['data'] = crypto.encrypt_item(self.item_key, b'not a plist', aad, iv=b'v' * 16)
                # The changed record id makes the original tag invalid in bad-auth-tag.
                records = {'synckey': [self.key], 'item': [self.item, bad]}
                store = FakeStore(session=JOINED)
                client = octagon.OctagonClient.__new__(octagon.OctagonClient)
                client.record = copy.deepcopy(JOINED)
                client.fetch_recoverable_tlks = lambda: ({'tlk': self.tlk}, [])
                client.sync_keychain = lambda: records
                with patch.object(octagon, 'load_peer_keys', return_value=type('Keys', (), {
                        'encryption': type('Encryption', (), {'private_key': None})()})()):
                    with self.assertRaises(AppleError):
                        apple._sync_with(_ctx(store), JOINED, None, None, client)
                self.assertEqual(store.applied, [])
                self.assertIsNone(store.sync_status.get('synced_at'))

    def test_a_complete_snapshot_decrypts_normally(self):
        store = pipeline.build_credential_store({'synckey': [self.key], 'item': [self.item]},
                                                'peer', None, {'tlk': self.tlk})
        self.assertEqual([(c.domain, c.username, c.password) for c in store.all()],
                         [('example.com', 'alex', 'password')])

    def test_incomplete_or_repeated_pages_are_refused(self):
        for pages in ([{'records': [], 'status': 1, 'continuation_token': None}],
                      [{'records': [], 'status': 99}],
                      [{'records': [], 'status': 1, 'continuation_token': b'x'}] * 2):
            with self.subTest(pages=pages):
                client = octagon.OctagonClient.__new__(octagon.OctagonClient)
                client.user_id = 'user'
                client.transport = type('Transport', (), {'fetch_records': lambda *a: b'page'})()
                # An extra final page bounds the unfixed implementation's repeated-token loop.
                with patch.object(octagon.ckks, 'parse_retrieve_changes_response',
                                  side_effect=pages + [{'records': [], 'status': 3}]):
                    with self.assertRaises(octagon.OctagonError):
                        client.sync_keychain(zones=('Passwords',))
