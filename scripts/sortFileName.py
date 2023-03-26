import sys,os
folder = sys.argv[1]
if os.path.isdir(folder):
    files = os.listdir(folder)
    files.sort(key=lambda x: (x.split('.')[0]))
    for file in files:
        os.system("type " + folder + "\\" + file + ">> test.txt")
