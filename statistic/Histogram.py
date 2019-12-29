import matplotlib.pyplot as plt


class Histogram:

    def __init__(self, bins=30, normalize=False, interval=0.0):
        self.hist_data = list()
        self.bins = bins
        if interval != 0.0:
            self.bins = round(1/interval)
        self.normalize = normalize

    def add_data_to_histogram(self, data_list):
        self.hist_data += data_list

    def plot(self):
        if self.normalize:
            axes = plt.axes()
            axes.set_ylim([0, 1])

        x, bins, p = plt.hist(self.hist_data, bins=self.bins, range=[0, 1], density=True)

        if self.normalize:
            normelizer = 0.0
            for item in p:
                if item.get_height() > normelizer:
                    normelizer = item.get_height()
            for item in p:
                item.set_height(item.get_height()/normelizer)
        print("Plot:")
        print("Interval: " + str(1/self.bins))
        print("Instances: " + str(len(self.hist_data)))
        print("Bins: " + str(self.bins))
        plt.show()


