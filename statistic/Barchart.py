import numpy as np
import matplotlib.pyplot as plt


class Barchart:

    def __init__(self):
        self.bar_data = list()
        self.x = list()
        self.set_x(interval=0.04)

    def set_x(self, interval=0.02, x_min=0, x_max=1):
        x = [0.0]
        while x[-1] <= x_max:
            x.append(x[-1] + interval)

        self.x = x
        self.bar_data = [0.0] * len(self.x)

    def insert_list(self, data_list):
        for e in data_list:
            self.insert(e)

    def insert(self, value):
        i = 0
        for intervals in self.x:
            i += 1
            if value < intervals:
                self.bar_data[i] += value
                break

    def plot(self):
        print(self.bar_data)
        print(self.x)
        y_pos = np.arange(len(self.x))
        plt.bar(y_pos, self.bar_data, align='center')
        plt.xticks(y_pos, self.x)
        plt.show()
