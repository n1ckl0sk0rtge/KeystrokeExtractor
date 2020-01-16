
class ExtendedPackage:

    def __init__(self, package, package_id=None):
        self.package = package
        self.id = package_id
        self.time = package.time
        self.keystroke = str()

    def __len__(self):
        return len(self.package)


