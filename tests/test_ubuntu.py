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

# FIXME: These should be using crafted XML rather than having to use
# the UbuntuOval ingestion fixture, this is *not* unit testing
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

def test_usns(ubuntu_oval):
    vuln = ubuntu_oval.vulnerabilities()[3300] #Random sample with a USN in, sorry :(
    assert "https://usn.ubuntu.com/usn/usn-3916-1" in vuln.advisory_references()
    assert vuln.usns() == ['USN-3916-1']

def test_dpkg_info(ubuntu_oval):
    assert ubuntu_oval._dpkg_info == []
    info = ubuntu_oval.dpkg_info()[0]
    assert ubuntu_oval._dpkg_info != []
    assert info.names() != []
    assert info.names()[0] == 'cpp-4.8' 
    assert info.ref() == "200224390000000"
    # Just a randomly chosen example of a dpkginfo_object using a reference to a variable containing package names
    roundcube_info = list(filter(lambda x: x._id == "oval:com.ubuntu.bionic:obj:201140780000000", ubuntu_oval.dpkg_info()))[0]
    assert roundcube_info.names() == ['roundcube',
                                      'roundcube-core',
                                      'roundcube-mysql',
                                      'roundcube-pgsql',
                                      'roundcube-plugins',
                                      'roundcube-sqlite3']

def test_dpkg_info_states(ubuntu_oval):
    assert ubuntu_oval._dpkg_info_states == []
    state = ubuntu_oval.dpkg_info_states()[0]
    assert ubuntu_oval._dpkg_info_states != []
    assert state.version_string() == "4.8.2-19ubuntu1"
    assert state.ref() == "200224390000000"


def test_criterion(ubuntu_oval):
    # Some ntfs-3g vuln
    ref = "201997550000000"
    vuln = list(filter(lambda x: x._id == f"oval:com.ubuntu.bionic:def:{ref}", ubuntu_oval.vulnerabilities()))[0]
    assert vuln.criteria()[0].ref() == ref

@pytest.mark.slow
def test_can_find_package(ubuntu_oval):
    roundcube_infos = [dpkg_info for dpkg_info in ubuntu_oval.dpkg_info() if "roundcube" in dpkg_info.names()]
    assert roundcube_infos[0].ref() == '201140780000000'

@pytest.mark.slow
def test_can_search_by_ref(ubuntu_oval):
    assert ubuntu_oval.get_vulnerabilities_by_ref('201140780000000').ref() == '201140780000000'
