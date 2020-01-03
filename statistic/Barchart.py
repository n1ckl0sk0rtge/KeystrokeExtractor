import numpy as np
import matplotlib.pyplot as plt
from termcolor import colored


class Barchart:

    def __init__(self):
        self.bar_data = list()
        self.x = list()
        self.set_x(interval=0.02)

    def set_x(self, interval=0.02, x_min=0, x_max=1):
        x = [0.0]
        while x[-1] <= x_max:
            x.append(round(x[-1] + interval, 3))

        self.x = x
        self.bar_data = [0.0] * len(self.x)

    def add_data_to_barchart(self, data_list):
        for e in data_list:
            self.insert(e)

    def insert(self, value):
        i = 0
        for intervals in self.x:
            i += 1
            if value < intervals:
                self.bar_data[i] += value
                break
            elif i == len(self.bar_data) - 1:
                break

    def plot(self):
        _data = list()
        for i in range(0, len(self.bar_data) - 1):
            _data.append((self.bar_data[i], self.x[i]))

        _data.sort(key=lambda tup: tup[0], reverse=True)
        print(colored("\nBarchartPlot:", "green"))
        print(_data)
        y_pos = np.arange(len([e[1] for e in _data]))
        plt.bar(y_pos, [e[0] for e in _data], align='center')
        plt.xticks(y_pos, [e[1] for e in _data], rotation='vertical')
        plt.show()
