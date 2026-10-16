"""Pin the credential-extraction behaviour behind the L3 per-(host, cred) cap.

The cap keys on the identifier returned by ``_extract_credential``. If a command
slips through with no identifier, the cap never counts it and the credential lock
is evadable — most famously by adding a flag that takes its own value (``ssh -o
ConnectTimeout=1 root@host``), which the old flag-skipping regex could not cross.
"""

from evilkit.harness import _extract_credential


def test_sshpass_password_and_user():
    assert _extract_credential("sshpass -p pw ssh svc@10.0.0.5 id") == "svc:pw"


def test_sshpass_quoted_password():
    assert _extract_credential("sshpass -p 'pw' ssh root@10.0.0.5") == "root:pw"


def test_bare_ssh_ip():
    assert _extract_credential("ssh root@10.0.0.5") == "root"


def test_bare_ssh_hostname():
    assert _extract_credential("ssh root@files01") == "root"


def test_ssh_short_flag_with_value():
    assert _extract_credential("ssh -p 22 root@10.0.0.5") == "root"


def test_ssh_long_flag_with_value():
    # Regression: `-o` takes its own value; the old regex stopped at the first
    # non-flag token and returned '' — so this cred never counted toward the cap.
    assert _extract_credential("ssh -o ConnectTimeout=1 root@10.0.0.5") == "root"


def test_ssh_multiple_flags_with_values():
    assert _extract_credential("ssh -o ConnectTimeout=1 -i id_rsa root@10.0.0.5") == "root"


def test_sshpass_with_flag_values():
    assert _extract_credential("sshpass -p pw ssh -o ConnectTimeout=1 root@10.0.0.5") == "root:pw"


def test_netexec():
    assert _extract_credential("nxc smb 10.0.0.5 -u admin -p admin") == "admin:admin"


def test_curl():
    assert _extract_credential("curl -u user:pass http://10.0.0.5") == "user:pass"


def test_smbclient():
    assert _extract_credential("smbclient //10.0.0.5/share -U user%pass") == "user:pass"


def test_hydra():
    assert _extract_credential("hydra -l user -p pass ssh://10.0.0.5") == "user:pass"


def test_no_credential():
    assert _extract_credential("ls -la /tmp") == ""
