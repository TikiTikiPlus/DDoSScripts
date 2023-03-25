import sys,os
folder = sys.argv[1]
if os.path.isdir(folder):
    files = os.listdir(folder)
    files.sort(key=lambda x: (x.split('.')[0]))
    concatenatedFiles=""
    for file in files:

        if os.path.isfile(folder+"\\"+file): 
            concatenatedFiles = concatenatedFiles + folder + "\\"+file + " " 
        
    print(concatenatedFiles)
    os.system("cat " + concatenatedFiles)