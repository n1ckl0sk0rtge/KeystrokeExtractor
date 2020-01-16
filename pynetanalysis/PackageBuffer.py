from collections import deque


class PackageBuffer:

    def __init__(self, size):
        self.buffer = deque()
        self.size = size

    def buffer_cleaner(self):
        while len(self.buffer) > self.size:
            self.buffer.popleft()

    def add(self, e):
        self.buffer.append(e)
        self.buffer_cleaner()

    def pop(self):
        return self.buffer.pop()

    def popleft(self):
        return self.buffer.popleft()

    def __getitem__(self, item):
        return self.buffer[item]

    def __setitem__(self, key, value):
        self.buffer[key] = value

    def get_last_as_package(self):
        if len(self.buffer) == 0:
            return None
        else:
            return self.buffer[-1].package

    def get_last_as_package_id(self):
        if len(self.buffer) == 0:
            return None
        else:
            return self.buffer[-1].id

    def __str__(self):
        return str(["package" for e in self.buffer])
