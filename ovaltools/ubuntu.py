from lxml import etree
from ovaltools.common import OvalObject
import re

release_parse = lambda x: re.match('^oval:com\.ubuntu\.(.+):def:100$', x)[1]

class Vulnerability(OvalObject):
    def __init__(self, xml):
        super().__init__(xml)

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
        return [criterion.attrib for criterion in criteria]

class Criterion(OvalObject):
    pass

class DpkgInfo(OvalObject):
    pass

class UbuntuOval:
    def __init__(self, oval_file_path):
        self._vulnerabilities = []
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

    def _parse_vulnerabilities(self):
        self._vulnerabilities = [Vulnerability(xml) for xml in self.xpath("//oval-def:definition[@class='vulnerability']")]
