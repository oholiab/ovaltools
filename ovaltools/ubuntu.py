from lxml import etree
from ovaltools.common import OvalObject
import re

release_parse = lambda x: re.match('^oval:com\.ubuntu\.(.+):def:100$', x)[1]

class Criterion(OvalObject):
    def __init__(self, xml):
        super().__init__(xml)
        self._test_ref = ""

    def ref(self):
        if self._test_ref == "":
            self._test_ref = self.xml.get('test_ref')
        if self._ref == "":
            self._ref = self._test_ref.split(":")[-1]
        return self._ref

class Vulnerability(OvalObject):
    def title(self):
        return self.xpath('oval-def:metadata/oval-def:title')[0].text

    def description(self):
        return self.xpath('oval-def:metadata/oval-def:description')[0].text

    def references(self):
        references = self.xpath('oval-def:metadata/oval-def:reference')
        return [ref.attrib for ref in references]

    def criteria(self):
        # These are not all of them, just the ones I care about.
        # TODO: Fix me, ensure that assumption that this is OR is correct
        criteria = self.xpath('oval-def:criteria//oval-def:criterion')
        return [Criterion(criterion) for criterion in criteria]

class DpkgInfoState(OvalObject):
    def __init__(self, xml):
        super().__init__(xml)
        self._version_string = None
        self._evr = None

    def version_string(self):
        if self._evr is None or self._version_string is None:
            self._evr = self.xpath('linux-def:evr')[0]
            self._version_string = self._evr.text
        return self._version_string

class DpkgInfo(OvalObject):
    def __init__(self, xml):
        super().__init__(xml)
        self._names = []
        self._var_refs = []

    def names(self):
        if self._names == []:
            names = self.xpath('linux-def:name')
            for name in names:
                if name.text == None:
                    # Need to add some code to look up name from this
                    self._var_refs.append(name.get('var_ref'))
                else:
                    self._names.append(name.text)
            for var_ref in self._var_refs:
                for value in self.xpath(f"//oval-def:constant_variable[@id='{var_ref}']/oval-def:value"):
                    self._names.append(value.text)
        return self._names

class UbuntuOval:
    def __init__(self, oval_file_path):
        self._vulnerabilities = []
        self._dpkg_info = []
        self._dpkg_info_states = []
        self.xml = etree.parse(oval_file_path)
        self.xml_element = self.xml.getroot()
        self.namespaces = self.xml_element.nsmap
        # XPath doesn't like it if you provide a namespace without a prefix
        self.xpath_namespaces = {k: v
                                 for k, v
                                 in self.namespaces.items()
                                 if k is not None}
        self.xpath_namespaces['oval-def'] = self.namespaces[None]
        inventory_id = self.xml_element.xpath("//oval-def:definition[@class='inventory']",
                                              namespaces=self.xpath_namespaces)[0].get('id')
        self.release = release_parse(inventory_id)

    def xpath(self, path):
        return self.xml_element.xpath(path, namespaces=self.xpath_namespaces)

    def vulnerabilities(self):
        if self._vulnerabilities == []:
            self._parse_vulnerabilities()
        return self._vulnerabilities

    def dpkg_info(self):
        if self._dpkg_info == []:
            self._parse_dpkg_info()
        return self._dpkg_info

    def dpkg_info_states(self):
        if self._dpkg_info_states == []:
            self._parse_dpkg_info_states()
        return self._dpkg_info_states

    def _parse_dpkg_info_states(self):
        self._dpkg_info_states = [DpkgInfoState(xml) for xml in self.xpath("//linux-def:dpkginfo_state")]

    def _parse_vulnerabilities(self):
        self._vulnerabilities = [Vulnerability(xml) for xml in self.xpath("//oval-def:definition[@class='vulnerability']")]

    def _parse_dpkg_info(self):
        self._dpkg_info = [DpkgInfo(xml) for xml in self.xpath("//linux-def:dpkginfo_object")]
