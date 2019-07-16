from ovaltools.ubuntu import UbuntuOval
from ovaltools.inventory import Inventory
from ovaltools.inventory import compare_versions
import os 
import pytest

dir_path = os.path.dirname(os.path.realpath(__file__))

TEST_FILE=f"{dir_path}/fixtures/com.ubuntu.bionic.cve.oval.xml"

# FIXME: These should be using crafted XML rather than having to use
# the UbuntuOval ingestion fixture, this is *not* unit testing
@pytest.fixture
def ubuntu_oval():
    return UbuntuOval(TEST_FILE)

@pytest.fixture
def inventory_vuln_unbound():
    i = Inventory("test")
    i.ingest_dpkg("unbound 1.6.7-1ubuntu2.0\n")
    return i

@pytest.mark.parametrize("ver1,operator,ver2,result", [
    ("1.6.7-1ubuntu2.0", "lt", "1.6.7-1ubuntu2.1", True),
    ("1.6.7-1ubuntu2.0", "eq", "1.6.7-1ubuntu2.1", False),
    ("1.6.7-1ubuntu2.0", "gt", "1.6.7-1ubuntu2.1", False),
    ("1.6.7-1ubuntu2.1", "eq", "1.6.7-1ubuntu2.1", True),
    ("1.6.7-1ubuntu2.1", "lt", "1.6.7-1ubuntu2.0", False),
    ])
def test_compare_versions(ver1, operator, ver2, result):
    assert compare_versions(ver1, operator, ver2) == result

# TODO: create a reduced oval manifest that doesn't take so long!
@pytest.mark.slow
def test_vulnerable(ubuntu_oval, inventory_vuln_unbound):
    u = ubuntu_oval
    i = inventory_vuln_unbound
    unbound_vuln_ref = '2017151050000000'
    unbound_vuln_package = 'unbound'
    i.process(u)
    assert i.package_match_refs == {unbound_vuln_ref: [unbound_vuln_package]}
    assert i.vulnerable_to_refs == {unbound_vuln_package: [unbound_vuln_ref]}
