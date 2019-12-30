
class ExtendedPackage:

    def __init__(self, package):
        self.package = package
        self.time = package.time
        self.keystroke = str()

    def __len__(self):
        return len(self.package)


