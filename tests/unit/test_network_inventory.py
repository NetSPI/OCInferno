"""Network-inventory extraction: IPs/CIDRs/URLs/FQDNs from resource rows."""
from __future__ import annotations

from ocinferno.modules.everything.utilities import network_inventory as ni


def _kinds(records):
    out = {}
    for r in records:
        out.setdefault(r["kind"], set()).add(r["value"])
    return out


def test_extracts_ips_cidrs_urls_fqdns_from_nested_json():
    rows = [{
        "id": "ocid1.loadbalancer.oc1..a", "display_name": "prod-lb",
        "compartment_id": "ocid1.compartment.oc1..c",
        "ip_addresses": '[{"ip_address":"129.146.10.20"},{"ip_address":"10.0.1.5"}]',
        "hostnames": '["app.example.com"]',
        "connection_urls": '{"u":"https://adb.us-phoenix-1.oraclecloud.com/ords/"}',
        "whitelisted_ips": '["203.0.113.0/24"]',
        "subnet_ids": '["ocid1.subnet.oc1..s1"]',
        "description": "finance database not a hostname",
    }]
    k = _kinds(ni.extract_from_rows("load_balancers", rows))
    assert "129.146.10.20" in k[ni.KIND_IP] and "10.0.1.5" in k[ni.KIND_IP]
    assert "203.0.113.0/24" in k[ni.KIND_CIDR]
    # CIDR base must NOT also be counted as a bare IP
    assert "203.0.113.0" not in k.get(ni.KIND_IP, set())
    assert "app.example.com" in k[ni.KIND_FQDN]
    assert "adb.us-phoenix-1.oraclecloud.com" in k[ni.KIND_FQDN]  # mined from URL host
    assert any(u.startswith("https://adb") for u in k[ni.KIND_URL])
    assert "ocid1.subnet.oc1..s1" in k[ni.KIND_NET_REF]


def test_description_text_does_not_produce_false_fqdn():
    # A non-host column with dotted words shouldn't yield FQDNs.
    rows = [{"id": "x", "description": "see config.file.here and readme.txt"}]
    k = _kinds(ni.extract_from_rows("some_table", rows))
    assert ni.KIND_FQDN not in k


def test_invalid_ip_octets_rejected():
    rows = [{"id": "x", "ip_address": "999.999.1.1 and 8.8.8.8"}]
    k = _kinds(ni.extract_from_rows("t", rows))
    assert "8.8.8.8" in k[ni.KIND_IP]
    assert "999.999.1.1" not in k.get(ni.KIND_IP, set())


def test_ocid_not_mistaken_for_fqdn():
    rows = [{"id": "x", "hostname": "ocid1.instance.oc1.phx.abc"}]
    k = _kinds(ni.extract_from_rows("t", rows))
    assert "ocid1.instance.oc1.phx.abc" not in k.get(ni.KIND_FQDN, set())


def test_dedupe_and_summarize():
    recs = ni.extract_from_rows("t", [{"id": "x", "ip_address": "1.1.1.1"}])
    recs = recs + recs  # duplicate
    deduped = ni.dedupe(recs)
    assert len(deduped) == 1
    summary = ni.summarize(deduped)
    assert summary["ip_distinct"] == 1
