from ovaltools.ubuntu import UbuntuOval
import os 
import pytest

dir_path = os.path.dirname(os.path.realpath(__file__))

TEST_FILE=f"{dir_path}/fixtures/com.ubuntu.bionic.cve.oval.xml"

def test_load_oval():
    u = UbuntuOval(TEST_FILE)
    assert u.xml is not None
    assert None not in u.xpath_namespaces.keys()
    assert u.release == 'bionic'

@pytest.fixture
def ubuntu_oval():
    return UbuntuOval(TEST_FILE)

def test_vulnerabilities_loading(ubuntu_oval):
    assert ubuntu_oval._vulnerabilities == []
    assert len(ubuntu_oval.vulnerabilities()) > 0
    assert ubuntu_oval._vulnerabilities != []

def test_vulnerability_attributes(ubuntu_oval):
    vuln = ubuntu_oval.vulnerabilities()[0]
    assert vuln._class == 'vulnerability'
    assert vuln.xpath_namespaces == ubuntu_oval.xpath_namespaces
    assert vuln.title() == 'CVE-2002-2439 on Ubuntu 18.04 LTS (bionic) - low.'
    assert vuln.references()[0]['ref_url'] == 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2439'
