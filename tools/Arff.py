from termcolor import colored


def create_arff_file(filename, number_of_attrib, data, classes):
    file = open(filename + ".arff", "w+")
    file.write("@Relation typing-" + filename.split("/")[-1] + "\n")
    for i in range(1, number_of_attrib):
        file.write("@ATTRIBUTE timestamp" + str(i) + " real" + "\n")

    arff_classes = ""

    try:
        for j in range(0, len(classes) - 1):
            arff_classes += classes.pop() + ","

        arff_classes += classes.pop()
    except:
        print(colored("Error: Set of classes is empty.", 'red'))

    file.write("@ATTRIBUTE class {" + arff_classes + "}\n")
    file.write("@DATA\n\n")

    try:
        for d in data:
            file.write(d)
    except:
        print(colored("Error: List of data is empty.", 'red'))

    file.close()
