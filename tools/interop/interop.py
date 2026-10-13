import subprocess, sys, os, shutil
from axolotl.ecc.curve import Curve
from axolotl.identitykey import IdentityKey
from axolotl.identitykeypair import IdentityKeyPair
from axolotl.state.prekeybundle import PreKeyBundle
from axolotl.state.prekeyrecord import PreKeyRecord
from axolotl.state.signedprekeyrecord import SignedPreKeyRecord
from axolotl.sessionbuilder import SessionBuilder
from axolotl.sessioncipher import SessionCipher
from axolotl.protocol.prekeywhispermessage import PreKeyWhisperMessage
from axolotl.protocol.whispermessage import WhisperMessage
from axolotl.protocol.senderkeydistributionmessage import SenderKeyDistributionMessage
from axolotl.axolotladdress import AxolotlAddress
from axolotl.groups.groupsessionbuilder import GroupSessionBuilder
from axolotl.groups.groupcipher import GroupCipher
from axolotl.groups.senderkeyname import SenderKeyName
from axolotl.tests.inmemoryaxolotlstore import InMemoryAxolotlStore
from axolotl.tests.groups.inmemorysenderkeystore import InMemorySenderKeyStore

tool, base = sys.argv[1], sys.argv[2]
shutil.rmtree(base, ignore_errors=True); os.makedirs(base)
checks = 0
def run(*args):
    p = subprocess.run([tool] + list(args), capture_output=True, text=True)
    out = p.stdout.strip()
    assert p.returncode == 0 and not out.startswith('ERR'), (args[0], out, p.stderr)
    return out
def ok(cond, what):
    global checks
    checks += 1
    if not cond:
        print('FAIL', what); sys.exit(1)
def priv(kp): return kp.getPrivateKey().serialize().hex()
def pub32(k): return k.serialize()[1:].hex()

# ---- 1. Python Alice -> C Bob ------------------------------------------
cdir = base + '/cbob'
bob_id = Curve.generateKeyPair(); spk = Curve.generateKeyPair(); otk = Curve.generateKeyPair()
run('init', cdir, priv(bob_id), priv(spk), '1', '1234', priv(otk), '7')
sig = Curve.calculateSignature(bob_id.getPrivateKey(), spk.getPublicKey().serialize())
alice = InMemoryAxolotlStore()
bundle = PreKeyBundle(1234, 1, 7, otk.getPublicKey(), 1, spk.getPublicKey(), sig,
                      IdentityKey(bob_id.getPublicKey()))
SessionBuilder(alice, alice, alice, alice, 'bob', 1).processPreKeyBundle(bundle)
ac = SessionCipher(alice, alice, alice, alice, 'bob', 1)
m1 = ac.encrypt(b'hello 1')
ok(bytes.fromhex(run('decrypt', cdir, 'alice:1', 'pk', m1.serialize().hex())) == b'hello 1', 'C decrypts python pkmsg')
m2 = ac.encrypt(b'hello 2')
ok(bytes.fromhex(run('decrypt', cdir, 'alice:1', 'pk', m2.serialize().hex())) == b'hello 2', 'C decrypts second pkmsg')
typ, hx = run('encrypt', cdir, 'alice:1', b'reply 1'.hex()).split()
ok(typ == 'msg', 'C reply is msg')
ok(ac.decryptMsg(WhisperMessage(serialized=bytes.fromhex(hx))) == b'reply 1', 'python decrypts C reply')
m3 = ac.encrypt(b'hello 3')
ok(type(m3).__name__ == 'WhisperMessage', 'python now sends WhisperMessage')
ok(bytes.fromhex(run('decrypt', cdir, 'alice:1', 'msg', m3.serialize().hex())) == b'hello 3', 'C decrypts after ratchet')
m4 = ac.encrypt(b'hello 4'); m5 = ac.encrypt(b'hello 5')
ok(bytes.fromhex(run('decrypt', cdir, 'alice:1', 'msg', m5.serialize().hex())) == b'hello 5', 'C decrypts out of order (5)')
ok(bytes.fromhex(run('decrypt', cdir, 'alice:1', 'msg', m4.serialize().hex())) == b'hello 4', 'C decrypts skipped (4)')
for i in range(3):
    typ, hx = run('encrypt', cdir, 'alice:1', ('r%d' % i).encode().hex()).split()
    ok(ac.decryptMsg(WhisperMessage(serialized=bytes.fromhex(hx))) == ('r%d' % i).encode(), 'python decrypts C %d' % i)
    m = ac.encrypt(('a%d' % i).encode())
    ok(bytes.fromhex(run('decrypt', cdir, 'alice:1', 'msg', m.serialize().hex())) == ('a%d' % i).encode(), 'ping-pong %d' % i)
print('python->C sessions ok')

# ---- 2. C Alice -> Python Bob ------------------------------------------
adir = base + '/calice'
a_id = Curve.generateKeyPair(); a_spk = Curve.generateKeyPair()
run('init', adir, priv(a_id), priv(a_spk), '1', '4321')
bob = InMemoryAxolotlStore()
bkp = bob.getIdentityKeyPair()
b_spk = Curve.generateKeyPair()
b_sig = Curve.calculateSignature(bkp.getPrivateKey(), b_spk.getPublicKey().serialize())
bob.storeSignedPreKey(1, SignedPreKeyRecord(1, 0, b_spk, b_sig))
b_otk = Curve.generateKeyPair()
bob.storePreKey(9, PreKeyRecord(9, b_otk))
run('bundle', adir, 'bob:1', str(bob.getLocalRegistrationId()), pub32(bkp.getPublicKey().getPublicKey()),
    '1', pub32(b_spk.getPublicKey()), b_sig.hex() if isinstance(b_sig, bytes) else bytes(b_sig).hex(),
    '9', pub32(b_otk.getPublicKey()))
bc = SessionCipher(bob, bob, bob, bob, 'alice', 1)
typ, hx = run('encrypt', adir, 'bob:1', b'from C 1'.hex()).split()
ok(typ == 'pk', 'C first message is pkmsg')
ok(bc.decryptPkmsg(PreKeyWhisperMessage(serialized=bytes.fromhex(hx))) == b'from C 1', 'python decrypts C pkmsg')
typ, hx = run('encrypt', adir, 'bob:1', b'from C 2'.hex()).split()
ok(typ == 'pk', 'still pkmsg before reply')
ok(bc.decryptPkmsg(PreKeyWhisperMessage(serialized=bytes.fromhex(hx))) == b'from C 2', 'python decrypts 2nd pkmsg')
r = bc.encrypt(b'bob reply')
ok(bytes.fromhex(run('decrypt', adir, 'bob:1', 'msg', r.serialize().hex())) == b'bob reply', 'C decrypts python reply')
typ, hx = run('encrypt', adir, 'bob:1', b'from C 3'.hex()).split()
ok(typ == 'msg', 'C switches to msg after reply')
ok(bc.decryptMsg(WhisperMessage(serialized=bytes.fromhex(hx))) == b'from C 3', 'python decrypts C msg')
print('C->python sessions ok')

# ---- 3. sender keys -----------------------------------------------------
store = InMemorySenderKeyStore()
name = SenderKeyName('120363@g.us', AxolotlAddress('alice', 1))
skdm = GroupSessionBuilder(store).create(name)
run('skdm_process', cdir, '120363@g.us', 'alice:1', skdm.serialize().hex())
gc = GroupCipher(store, name)
msgs = [gc.encrypt(('grp %d' % i).encode()) for i in range(4)]
ok(bytes.fromhex(run('sk_decrypt', cdir, '120363@g.us', 'alice:1', bytes(msgs[0]).hex())) == b'grp 0', 'C decrypts group msg')
ok(bytes.fromhex(run('sk_decrypt', cdir, '120363@g.us', 'alice:1', bytes(msgs[3]).hex())) == b'grp 3', 'C skips ahead')
ok(bytes.fromhex(run('sk_decrypt', cdir, '120363@g.us', 'alice:1', bytes(msgs[2]).hex())) == b'grp 2', 'C uses skipped key')

dist = bytes.fromhex(run('sk_dist', cdir, '120363@g.us', 'me:5'))
store2 = InMemorySenderKeyStore()
name2 = SenderKeyName('120363@g.us', AxolotlAddress('me', 5))
GroupSessionBuilder(store2).process(name2, SenderKeyDistributionMessage(serialized=dist))
gc2 = GroupCipher(store2, name2)
for i in range(3):
    ct = bytes.fromhex(run('sk_encrypt', cdir, '120363@g.us', 'me:5', ('mine %d' % i).encode().hex()))
    ok(gc2.decrypt(ct) == ('mine %d' % i).encode(), 'python decrypts C group msg %d' % i)
print('sender keys ok')
print('interop: %d checks passed' % checks)
