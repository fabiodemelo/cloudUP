#!/usr/bin/env python3
"""End-to-end test of the deployed CloudUp sync API (docs/sync-api.md).

    python3 server/tests/api_test.py [--base URL]

Python 3.9+ stdlib only. It needs the `demelos` ssh alias: the test secret is
read from the server's env file over ssh (kept in memory, never printed), and
the database is checked over ssh after the account is deleted.

The server never checks key cryptography, only hashes, so random bytes stand in
for auth_key, wrapped keys and vault blobs. Every account uses a throwaway
cloudup-test+<random>@demelos.com address: the server sends no mail to those,
and with the X-CloudUp-Test header it returns the emailed code in the reply.
All test accounts are deleted at the end, whatever happens.
"""
import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.request

BASE = "https://www.demelos.com/tools/cloudup/api/v1/"
SSH = ["ssh", "-o", "RemoteCommand=none", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "demelos"]
ENV_FILE = "/home/demelos.com/cloudup-api.env"
UA = "CloudUp-APITest/1.0"
TEST_SECRET = ""
PASSED = 0


def b64(raw):
    return base64.b64encode(raw).decode()


def rnd(n):
    return b64(os.urandom(n))


def test_email():
    return "cloudup-test+%s@demelos.com" % secrets.token_hex(6)


def ssh(cmd):
    out = subprocess.run(SSH + [cmd], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError("ssh command failed: %s" % out.stderr.strip()[-300:])
    return out.stdout


def sql(query):
    # Test emails are [a-z0-9+@.] only, so they are safe inside the query.
    return ssh("sudo -n mysql -N -B cloudup -e %s" % json.dumps(query)).strip()


def call(method, path, body=None, token=None, test=False, headers=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if test:
        req.add_header("X-CloudUp-Test", TEST_SECRET)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    parsed = None
    if raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw.decode(errors="replace")[:200]
    return status, parsed


def check(cond, what, detail=None):
    global PASSED
    if not cond:
        raise AssertionError("FAIL: %s %s" % (what, "" if detail is None else "-> %r" % (detail,)))
    PASSED += 1
    print("  ok  %s" % what)


def expect(resp, status, what):
    check(resp[0] == status, "%s (HTTP %d)" % (what, status), resp)
    return resp[1]


def clear_limits(*emails):
    st, body = call("POST", "test/reset-limits", {"emails": list(emails)}, test=True)
    if st != 204:
        raise RuntimeError("could not clear rate limits: %r %r" % (st, body))


def new_keys():
    return {
        "salt": rnd(16),
        "kdf": {"alg": "argon2id", "m": 65536, "t": 3, "p": 1},
        "auth_key": rnd(32),
        "wrapped_vault_key": rnd(72),
        "recovery_wrapped_vault_key": rnd(72),
        "recovery_auth": rnd(32),
    }


def register(email, keys, test=True):
    return call("POST", "register", dict(email=email, **keys), test=test)


def login(email, auth_key, device="Test Mac"):
    return call("POST", "login", {"email": email, "auth_key": auth_key, "device_name": device})


def run(created):
    a = test_email()
    unknown = test_email()
    created += [a, unknown]
    clear_limits(a, unknown)

    print("prelogin")
    s1 = expect(call("POST", "prelogin", {"email": unknown}), 200, "unknown email gets kdf and salt")
    s2 = expect(call("POST", "prelogin", {"email": unknown.upper()}), 200, "same unknown email, other case")
    check(s1["salt"] == s2["salt"] and len(base64.b64decode(s1["salt"])) == 16, "unknown email salt is stable, 16 bytes")
    check(s1["kdf"] == {"alg": "argon2id", "m": 65536, "t": 3, "p": 1}, "default kdf", s1["kdf"])
    expect(call("POST", "prelogin", {"email": "not-an-email"}), 400, "bad email rejected")
    expect(call("POST", "prelogin", {}), 400, "missing email rejected")

    pre_a = expect(call("POST", "prelogin", {"email": a}), 200, "prelogin before sign-up")["salt"]

    print("register and verify")
    k = new_keys()
    bad = dict(k, auth_key=rnd(31))
    expect(register(a, bad), 400, "31-byte auth_key rejected")
    expect(register(a, dict(k, kdf={"alg": "argon2id", "m": 1024, "t": 1, "p": 1})), 400, "weak kdf rejected")
    expect(register(a, dict(k, salt="not base64!")), 400, "bad base64 rejected")
    r = expect(register(a, k, test=False), 202, "register")
    check(r == {"status": "verify"}, "no code in the reply without the test header", r)
    r = expect(register(a, k), 202, "register again replaces the unverified account")
    code = r.get("test_code", "")
    check(len(code) == 6 and code.isdigit(), "test mode returns the 6-digit code")
    r = expect(call("POST", "resend", {"email": a}), 202, "resend")
    check("test_code" not in r, "resend without test header hides the code", r)
    r = expect(call("POST", "resend", {"email": a}, test=True), 202, "resend with test header")
    code = r["test_code"]
    p = expect(call("POST", "prelogin", {"email": a}), 200, "prelogin while unverified")
    check(p["salt"] == pre_a != k["salt"], "unverified account still gets the fake salt, not its own")
    expect(login(a, k["auth_key"]), 401, "login before verifying is refused like a wrong password")
    wrong = "%06d" % ((int(code) + 1) % 1000000)
    e = expect(call("POST", "verify", {"email": a, "code": wrong, "device_name": "Mac A"}), 401, "wrong code")
    check(e["error"] == "bad_code", "error is bad_code", e)
    v = expect(call("POST", "verify", {"email": a, "code": code, "device_name": "Mac A"}), 200, "verify")
    check(v["wrapped_vault_key"] == k["wrapped_vault_key"] and v["vault_version"] == 0, "verify returns wrapped key, version 0", v)
    t1 = v["token"]
    check(len(t1) == 43, "token is 32 bytes base64url")
    expect(call("POST", "verify", {"email": a, "code": code, "device_name": "Mac A"}), 401, "code works only once")

    print("prelogin for a known email")
    p1 = expect(call("POST", "prelogin", {"email": a}), 200, "prelogin known")
    p2 = expect(call("POST", "prelogin", {"email": a}), 200, "prelogin known again")
    check(p1["salt"] == k["salt"] == p2["salt"] and p1["kdf"] == k["kdf"], "known email gets its registered salt and kdf")

    print("register on a verified email")
    r = expect(register(a, new_keys()), 202, "register on a verified email answers 202")
    check(r == {"status": "verify"}, "and gives nothing away", r)

    print("login")
    clear_limits(a, unknown)
    e = expect(login(a, rnd(32)), 401, "wrong auth_key")
    check(e["error"] == "bad_credentials", "error is bad_credentials", e)
    e2 = expect(login(unknown, rnd(32)), 401, "unknown email")
    check(e2 == e, "unknown email and wrong password look the same", (e, e2))
    l2 = expect(login(a, k["auth_key"], "Mac B"), 200, "login")
    t2 = l2["token"]
    check(l2["wrapped_vault_key"] == k["wrapped_vault_key"] and l2["vault_version"] == 0, "login returns wrapped key and version")
    acct = expect(call("GET", "account", token=t1), 200, "GET account")
    check(acct["email"] == a and acct["vault_version"] == 0 and acct["vault_updated_at"] is None, "account fields", acct)
    expect(call("GET", "account"), 401, "no token")
    expect(call("GET", "account", token="A" * 43), 401, "unknown token")

    print("vault")
    expect(call("GET", "vault", token=t1), 204, "no vault yet")
    blob1 = rnd(5000)
    r = expect(call("PUT", "vault", {"base_version": 0, "blob": blob1}, token=t1), 200, "first upload")
    check(r == {"version": 1}, "version 1", r)
    g = expect(call("GET", "vault", token=t2), 200, "GET vault from the other Mac")
    check(g["version"] == 1 and g["blob"] == blob1 and g["updated_at"].endswith("Z"), "same blob back", g.get("version"))
    c = expect(call("PUT", "vault", {"base_version": 0, "blob": rnd(100)}, token=t2), 409, "stale base_version")
    check(c["error"] == "conflict" and c["version"] == 1 and c["blob"] == blob1, "409 carries the current vault")
    blob2 = rnd(1536 * 1024)  # 2 MiB of base64, exactly the cap
    check(len(blob2) == 2 * 1024 * 1024, "test blob is exactly 2 MiB of base64")
    r = expect(call("PUT", "vault", {"base_version": 1, "blob": blob2}, token=t2), 200, "upload at the 2 MiB cap")
    check(r == {"version": 2}, "version 2", r)
    expect(call("PUT", "vault", {"base_version": 2, "blob": rnd(1536 * 1024 + 3)}, token=t1), 413, "over 2 MiB rejected")
    expect(call("PUT", "vault", {"base_version": 2, "blob": "%%%%"}, token=t1), 400, "bad base64 blob rejected")
    expect(call("PUT", "vault", {"base_version": "2", "blob": blob1}, token=t1), 400, "string base_version rejected")
    acct = expect(call("GET", "account", token=t1), 200, "account after uploads")
    check(acct["vault_version"] == 2 and acct["vault_updated_at"], "account shows vault version 2", acct)

    print("devices")
    clear_limits(a, unknown)
    t3 = expect(login(a, k["auth_key"], "Mac C"), 200, "third device")["token"]
    d = expect(call("GET", "devices", token=t1), 200, "GET devices")
    names = sorted(x["name"] for x in d)
    check(names == ["Mac A", "Mac B", "Mac C"], "three devices listed", names)
    check([x["name"] for x in d if x["current"]] == ["Mac A"], "current device flagged")
    c_id = [x["id"] for x in d if x["name"] == "Mac C"][0]
    expect(call("DELETE", "devices/%d" % c_id, token=t1), 204, "revoke Mac C")
    expect(call("GET", "account", token=t3), 401, "revoked token no longer works")
    expect(call("DELETE", "devices/%d" % c_id, token=t1), 404, "revoking twice is 404")
    expect(call("DELETE", "devices/abc", token=t1), 404, "bad device id is 404")
    t4 = expect(login(a, k["auth_key"], "Mac D"), 200, "fourth device")["token"]
    expect(call("POST", "logout", token=t4), 204, "logout")
    expect(call("GET", "account", token=t4), 401, "logged-out token no longer works")

    print("password change")
    clear_limits(a, unknown)
    k2 = dict(salt=rnd(16), kdf={"alg": "argon2id", "m": 131072, "t": 3, "p": 1}, auth_key=rnd(32), wrapped=rnd(72))
    body = {"auth_key": rnd(32), "new_salt": k2["salt"], "new_kdf": k2["kdf"], "new_auth_key": k2["auth_key"],
            "new_wrapped_vault_key": k2["wrapped"]}
    expect(call("POST", "password", body, token=t1), 401, "wrong current auth_key")
    body["auth_key"] = k["auth_key"]
    expect(call("POST", "password", body, token=t1), 204, "password changed")
    expect(call("GET", "account", token=t2), 401, "other device signed out")
    expect(call("GET", "account", token=t1), 200, "this device stays signed in")
    p = expect(call("POST", "prelogin", {"email": a}), 200, "prelogin after change")
    check(p["salt"] == k2["salt"] and p["kdf"]["m"] == 131072, "new salt and raised kdf")
    expect(login(a, k["auth_key"]), 401, "old auth_key refused")
    l = expect(login(a, k2["auth_key"]), 200, "new auth_key works")
    check(l["wrapped_vault_key"] == k2["wrapped"] and l["vault_version"] == 2, "new wrapped key, vault kept")

    print("recovery key")
    clear_limits(a, unknown)
    expect(call("POST", "recover/start", {"email": a, "recovery_auth": rnd(32)}), 401, "wrong recovery_auth")
    expect(call("POST", "recover/start", {"email": unknown, "recovery_auth": rnd(32)}), 401, "unknown email")
    rs = expect(call("POST", "recover/start", {"email": a, "recovery_auth": k["recovery_auth"]}), 200, "recover/start")
    check(rs["recovery_wrapped_vault_key"] == k["recovery_wrapped_vault_key"] and len(rs["reset_token"]) == 43,
          "returns recovery-wrapped key and token")
    k3 = dict(salt=rnd(16), kdf=k["kdf"], auth_key=rnd(32), wrapped_vault_key=rnd(72))
    expect(call("POST", "recover/finish", dict(reset_token="B" * 43, device_name="Mac R", **k3)), 401, "bad reset token")
    rf = expect(call("POST", "recover/finish", dict(reset_token=rs["reset_token"], device_name="Mac R", **k3)), 200,
                "recover/finish")
    check(rf["vault_version"] == 2, "vault kept after recovery", rf)
    expect(call("POST", "recover/finish", dict(reset_token=rs["reset_token"], device_name="Mac R", **k3)), 401,
           "reset token works once")
    expect(call("GET", "account", token=t1), 401, "old sessions signed out")
    t5 = rf["token"]
    expect(call("GET", "account", token=t5), 200, "new session works")
    clear_limits(a, unknown)
    expect(login(a, k2["auth_key"]), 401, "previous password refused")
    expect(login(a, k3["auth_key"]), 200, "recovered password works")

    print("reset without recovery key")
    clear_limits(a, unknown)
    r = expect(call("POST", "reset/start", {"email": unknown}, test=True), 202, "reset/start unknown email")
    check("test_code" not in r, "no code for an unknown email", r)
    r = expect(call("POST", "reset/start", {"email": a}, test=True), 202, "reset/start")
    rcode = r["test_code"]
    k4 = new_keys()
    fin = dict(email=a, device_name="Mac Z", **k4)
    wrong = "%06d" % ((int(rcode) + 7) % 1000000)
    expect(call("POST", "reset/finish", dict(fin, code=wrong)), 401, "wrong reset code")
    rf = expect(call("POST", "reset/finish", dict(fin, code=rcode)), 200, "reset/finish")
    check(rf["vault_version"] == 0, "vault_version 0", rf)
    t6 = rf["token"]
    expect(call("GET", "account", token=t5), 401, "all old sessions signed out")
    expect(call("GET", "vault", token=t6), 204, "vault erased")
    expect(call("POST", "reset/finish", dict(fin, code=rcode)), 401, "reset code works once")
    clear_limits(a, unknown)
    expect(login(a, k3["auth_key"]), 401, "old password refused")
    expect(login(a, k4["auth_key"]), 200, "new password works")
    expect(call("POST", "recover/start", {"email": a, "recovery_auth": k["recovery_auth"]}), 401, "old recovery key refused")
    expect(call("POST", "recover/start", {"email": a, "recovery_auth": k4["recovery_auth"]}), 200, "new recovery key works")

    print("code attempt limit")
    d_email = test_email()
    created.append(d_email)
    clear_limits(a, unknown, d_email)
    kd = new_keys()
    dcode = expect(register(d_email, kd), 202, "register another account")["test_code"]
    for i in range(5):
        bad_code = "%06d" % ((int(dcode) + 1 + i) % 1000000)
        expect(call("POST", "verify", {"email": d_email, "code": bad_code}), 401, "wrong code %d/5" % (i + 1))
    expect(call("POST", "verify", {"email": d_email, "code": dcode}), 401, "right code refused after 5 misses")

    print("rate limits")
    clear_limits(a, unknown, d_email)
    for i in range(10):
        expect(login(unknown, rnd(32)), 401, "failed login %d/10" % (i + 1))
    st, e = login(unknown, rnd(32))
    check(st == 429 and e["error"] == "rate_limited" and isinstance(e["retry_after"], int) and 0 < e["retry_after"] <= 900,
          "11th login is 429 with retry_after", (st, e))
    clear_limits(a, unknown, d_email)
    for i in range(5):
        expect(call("POST", "resend", {"email": d_email}), 202, "resend %d/5" % (i + 1))
    st, e = call("POST", "resend", {"email": d_email})
    check(st == 429 and 3000 < e["retry_after"] <= 3600, "6th resend in an hour is 429", (st, e))
    clear_limits(a, unknown, d_email)
    expect(login(unknown, rnd(32)), 401, "limits cleared by the test endpoint")
    st, _ = call("POST", "test/reset-limits", {"emails": [a]})
    check(st == 404, "test endpoint is a 404 without the secret", st)
    st, _ = call("POST", "test/reset-limits", {"emails": ["someone@example.com"]}, test=True)
    check(st == 404, "test endpoint refuses non-test emails", st)

    print("delete account")
    uid = sql("SELECT id FROM users WHERE email='%s'" % a)
    check(uid.isdigit(), "account row exists", uid)
    t7 = expect(login(a, k4["auth_key"]), 200, "sign in")["token"]
    expect(call("PUT", "vault", {"base_version": 0, "blob": blob1}, token=t7), 200, "upload a vault")
    call("POST", "reset/start", {"email": a}, test=True)  # leaves a live reset code
    expect(call("DELETE", "account", {"auth_key": rnd(32)}, token=t7), 401, "wrong auth_key refused")
    expect(call("DELETE", "account", {"auth_key": k4["auth_key"]}, token=t7), 204, "account deleted")
    expect(call("GET", "account", token=t6), 401, "every session is gone")
    left = sql(
        "SELECT (SELECT COUNT(*) FROM users WHERE id=%s OR email='%s') + (SELECT COUNT(*) FROM sessions WHERE user_id=%s)"
        " + (SELECT COUNT(*) FROM vaults WHERE user_id=%s) + (SELECT COUNT(*) FROM codes WHERE user_id=%s)"
        " + (SELECT COUNT(*) FROM reset_tokens WHERE user_id=%s)" % (uid, a, uid, uid, uid, uid))
    check(left == "0", "no rows left for the deleted user", left)
    p = expect(call("POST", "prelogin", {"email": a}), 200, "prelogin after deletion")
    check(p["salt"] == pre_a, "deleted email gets the same fake salt as before sign-up")


def main():
    global BASE, TEST_SECRET
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", default=BASE)
    args = ap.parse_args()
    BASE = args.base.rstrip("/") + "/"
    TEST_SECRET = ssh("sudo -n sed -n 's/^TEST_SECRET=//p' %s" % ENV_FILE).strip()
    if len(TEST_SECRET) < 32:
        sys.exit("TEST_SECRET is not set in %s; test mode is off." % ENV_FILE)

    created = []
    ok = False
    try:
        run(created)
        ok = True
    except AssertionError as e:
        print(e)
    finally:
        if created:
            emails = ",".join("'%s'" % e for e in created)
            sql("DELETE FROM users WHERE email IN (%s)" % emails)
            remaining = sql("SELECT COUNT(*) FROM users WHERE email IN (%s)" % emails)
            clear_limits(*created)
            print("cleanup: %d test addresses, %s accounts left" % (len(created), remaining))
    print("%s: %d checks passed" % ("PASS" if ok else "FAIL", PASSED))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
