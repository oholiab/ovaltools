import subprocess

def compare_versions(version1, operator, version2):
    cmd = f"dpkg --compare-versions {version1} {operator} {version2}"
    returncode = subprocess.run(cmd.split(" ")).returncode
    if returncode == 0:
        return True
    else:
        return False

class Inventory():
    def __init__(self, identity):
        self.identity = identity
        self.package_name_version_dict = {}
        self.package_match_refs = {}
        self.vulnerable_to_refs = {}

    def ingest_dpkg(self, listing):
        """dpkg-query --showformat='${Package} ${Version}\n' --show"""
        package = 0
        version = 1
        for line in listing.split("\n"):
            entry = line.split(" ")
            if len(entry) < 2:
                continue
            self.package_name_version_dict[entry[package]] = entry[version]
            
    def process(self, oval_manifest):
        for info in oval_manifest.dpkg_info():
            for package_name in info.names():
                if package_name in self.package_name_version_dict.keys():
                    if self.package_match_refs.get(info.ref()) is None:
                        self.package_match_refs[info.ref()] = [package_name]
                    else:
                        self.package_match_refs[info.ref()].append(package_name)
        for state in oval_manifest.dpkg_info_states():
            if state.ref() in self.package_match_refs.keys():
                for package in self.package_match_refs[state.ref()]:
                    if compare_versions(self.package_name_version_dict[package], 'lt', state.version_string()):
                        if self.vulnerable_to_refs.get(state.ref()) is None:
                            self.vulnerable_to_refs[state.ref()] = [package]
                        else:
                            self.vulnerable_to_refs[state.ref()].append(package)
