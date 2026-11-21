#!/usr/bin/env python3
"""End-to-end test of the CloudUp license flow (docs/license-api.md).

    python3 server/tests/license_test.py                       # live server
    python3 server/tests/license_test.py --base URL --env FILE --mock URL

Live, it reads TEST_SECRET over ssh like api_test.py, issues real CloudUp
licenses for throwaway cloudup-test+<random>@demelos.com addresses (order_ref
cloudup-api-test) and deletes them from the license server at the end.

Locally, --env points at the env file the PHP server uses (TEST_SECRET and DB
login are read from it) and --mock at server/tests' mock of dmadmin, which adds
the checks that need a revoked license or a license-server outage.
"""
import argparse
import json
import re
import subprocess
import sys
import urllib.request

import api_test as t

KEY_RE = re.compile(r"^DM(-[0-9A-Z]{4}){6}$")
ADMIN_ENV = "/home/demelos.com/admin-portal/backend/.env"
MOCK = ""
LOCAL_DB = None  # (user, db) for a local run


def mock(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(MOCK.rstrip("/") + path, data=data, method="POST" if data else "GET")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"null")


def code_rows(email):
    q = "SELECT COUNT(*) FROM license_codes WHERE email='%s'" % email
    if LOCAL_DB:
        out = subprocess.run(["mysql", "-N", "-B", "-u", LOCAL_DB[0], LOCAL_DB[1], "-e", q],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    return t.sql(q)


def start(email, test=True):
    return t.call("POST", "license/start", {"email": email}, test=test)


def finish(email, code):
    return t.call("POST", "license/finish", {"email": email, "code": code})


def wrong(code):
    return "%06d" % ((int(code) + 1) % 1000000)


def run(created):
    a, b, c, d = t.test_email(), t.test_email(), t.test_email(), t.test_email()
    created += [a, b, c, d]
    t.clear_limits(a, b, c, d)

    print("license/start")
    t.expect(start("not-an-email"), 400, "bad email rejected")
    t.expect(t.call("POST", "license/start", {}), 400, "missing email rejected")
    st, body = start(d, test=False)
    t.check(st == 202 and "test_code" not in body, "no code in the reply without the test header", (st, body))
    code = t.expect(start(a.upper()), 202, "start, other case, test header")["test_code"]
    t.check(re.fullmatch(r"[0-9]{6}", code) is not None, "six-digit code", code)
    t.check(code_rows(a) == "1", "one live code per email", code_rows(a))
    again = t.expect(start(a), 202, "start again within a minute")
    t.check("test_code" not in again, "a code under a minute old isn't replaced", again)

    print("license/finish")
    e = t.expect(finish(a, wrong(code)), 401, "wrong code refused")
    t.check(e["error"] == "bad_code", "error is bad_code", e)
    t.expect(finish(a, "12ab56"), 400, "malformed code rejected")
    lic = t.expect(finish(a, code), 200, "right code gives a license")
    key = lic["license_key"]
    t.check(KEY_RE.match(key) is not None, "license key format DM-XXXX-…", key)
    t.check(lic["email"] == a and lic["max_activations"] == 5, "reply names email and 5 Macs", lic)
    t.expect(finish(a, code), 401, "a used code can't be reused")
    t.check(code_rows(a) == "0", "code row deleted after use", code_rows(a))

    code2 = t.expect(start(a), 202, "start again for the same email")["test_code"]
    again = t.expect(finish(a, code2), 200, "verify again")
    t.check(again["license_key"] == key, "same email gets the same key back", (key, again))

    print("attempt limit")
    code3 = t.expect(start(b), 202, "start for a second email")["test_code"]
    for i in range(5):
        t.expect(finish(b, wrong(code3)), 401, "wrong guess %d/5" % (i + 1))
    t.expect(finish(b, code3), 401, "right code dead after 5 wrong guesses")
    t.clear_limits(a, b, c)
    code3 = t.expect(start(b), 202, "a new code works again")["test_code"]
    other = t.expect(finish(b, code3), 200, "second email gets a license")
    t.check(other["license_key"] != key, "different emails get different keys", other)

    print("concurrent finishes")
    import threading
    e = t.test_email()
    created.append(e)
    code6 = t.expect(start(e), 202, "start for a new email")["test_code"]
    out = []
    ths = [threading.Thread(target=lambda: out.append(finish(e, code6))) for _ in range(2)]
    [th.start() for th in ths]
    [th.join() for th in ths]
    keys = {r[1]["license_key"] for r in out if r[0] == 200}
    t.check(len(keys) == 1, "two finishes at once give one key", out)

    if MOCK:
        print("license server problems (mock)")
        state = mock("/_state")
        mine = [l for l in state if l["email"] == a]
        t.check(len(mine) == 1 and mine[0]["max_activations"] == 5 and mine[0]["product_slug"] == "cloudup"
                and mine[0]["order_ref"] == "cloudup-api-test", "one cloudup license, 5 activations, test ref", mine)
        mock("/_down", {"down": True})
        code4 = t.expect(start(c), 202, "start while the license server is down")["test_code"]
        e = t.expect(finish(c, code4), 503, "license server down is a 503")
        t.check(e["error"] == "license_unavailable", "error is license_unavailable", e)
        mock("/_down", {"down": False})
        t.expect(finish(c, code4), 200, "the same code works once it is back")
        mock("/_set", {"email": c, "status": "revoked"})
        code5 = t.expect(start(c), 202, "start for a revoked license")["test_code"]
        e = t.expect(finish(c, code5), 403, "revoked license isn't replaced")
        t.check(e["error"] == "license_blocked", "error is license_blocked", e)

    print("rate limit")
    t.clear_limits(*created)
    for i in range(5):
        t.expect(start(a), 202, "start %d/5" % (i + 1))
    st, e = start(a)
    t.check(st == 429 and 3000 < e["retry_after"] <= 3600, "6th start in an hour is 429", (st, e))


def delete_live_licenses(created):
    env = t.ssh("sudo -n sed -n 's/^DB_NAME=//p' %s" % ADMIN_ENV).strip()
    if not re.fullmatch(r"[A-Za-z0-9_]+", env):
        print("cleanup: could not read the license database name; delete test licenses by hand")
        return
    emails = ",".join("'%s'" % e for e in created)
    where = "customer_email IN (%s) AND order_ref='cloudup-api-test'" % emails
    t.ssh("sudo -n mysql %s -e %s" % (env, json.dumps(
        "DELETE a FROM dmadmin_license_activations a JOIN dmadmin_licenses l ON l.id=a.license_id WHERE l.%s;"
        " DELETE FROM dmadmin_licenses WHERE %s" % (where, where))))
    left = t.ssh("sudo -n mysql -N -B %s -e %s" % (env, json.dumps(
        "SELECT COUNT(*) FROM dmadmin_licenses WHERE %s" % where))).strip()
    print("cleanup: %s test licenses left on the license server" % left)


def main():
    global MOCK, LOCAL_DB
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", default=t.BASE)
    ap.add_argument("--env", help="local env file (local run)")
    ap.add_argument("--mock", default="", help="mock dmadmin URL (local run)")
    args = ap.parse_args()
    t.BASE = args.base.rstrip("/") + "/"
    MOCK = args.mock
    if args.env:
        cfg = dict(l.split("=", 1) for l in open(args.env).read().splitlines() if "=" in l and l[0] != "#")
        t.TEST_SECRET = cfg["TEST_SECRET"]
        LOCAL_DB = (cfg["DB_USER"], cfg["DB_NAME"])
    else:
        t.TEST_SECRET = t.ssh("sudo -n sed -n 's/^TEST_SECRET=//p' %s" % t.ENV_FILE).strip()
    if len(t.TEST_SECRET) < 32:
        sys.exit("TEST_SECRET is not set; test mode is off.")

    created = []
    ok = False
    try:
        run(created)
        ok = True
    except AssertionError as e:
        print(e)
    finally:
        if created:
            t.clear_limits(*created)
            if not args.env:
                delete_live_licenses(created)
    print("%s: %d checks passed" % ("PASS" if ok else "FAIL", t.PASSED))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
