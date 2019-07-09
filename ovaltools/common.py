from lxml import etree

class OvalObject:
    def __init__(self, xml):
        self.xml = xml
        self._id = xml.get('id')
        self._class = xml.get('class')
        self.namespaces = xml.nsmap
        self.xpath_namespaces = {k: v
                                 for k, v
                                 in self.namespaces.items()
                                 if k is not None}
        self.xpath_namespaces['oval-def'] = self.namespaces[None]

    def xpath(self, path):
        return self.xml.xpath(path, namespaces=self.xpath_namespaces)
