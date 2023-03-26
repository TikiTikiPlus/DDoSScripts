import sys,os
folder = sys.argv[1]
concatenatedFiles=""
if os.path.isdir(folder):
    files = os.listdir(folder)
    files.sort(key=lambda x: (x.split('.')[0]))
    for file in files:
        concatenatedFiles = concatenatedFiles.join(folder + "\\" + file)
    os.system("cat " + concatenatedFiles + ">> test.txt")
