# Python code to pull out vulnerabilities from the NVD database.
#
# INPUT: Annual vulnerability data in JSON format.
#         -Download from: https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
#
# Included are 3 routines:
#   1) cveSearch: Reads the NVD JSON files,
#                 pulls out all entries matching a text string,
#                 and returns a dictionary containing the
#                 matching CVE IDs and published date.
#
#   2) cveSave: Reads in the dictionary from cveSearch and processes it.
#               Returns two numpy arrays, one with the time and
#                      and one with the associated accumulated vulnerabilities.
#               Includes an option to save these two arrays to a file.
#               
#
#   3) cvePlot: Takes two numpy arrays (time and vulnerabilities), and creates
#               a line plot.  Includes an option to save the figures.
#
#
# Created by Katherine Haynes, 9/29/2020

import json
import matplotlib.pyplot as plt
import numpy as np

# Specify information for the products you wish to pull out:
myText1 = 'apple:mac_os_x'
myJSON1 = 'MacOS.json'
mySave1 = 'MacOS.csv'
myTitle1 = 'MacOS Vulnerabilities'
myFig1 = 'MacOS.png'

myText2 = 'internet_information_server:'
myJSON2 = 'IIS.json'
mySave2 = 'IIS.csv'
myTitle2 = 'Internet Information Server HTTP Server Vulnerabilities'
myFig2 = 'IIS.png'

# Specify the years to check:
yrStart = 2002
yrStop = 2020

# Set where the data is located:
dataDir = '/Users/suj19/Dropbox/classes/cs559/homework/A2/nvd/'
dataPrefix = 'nvdcve-1.1-'
dataSuffix = '.json'

# Routine to search through specified years of a NVD database
# and pull out CVE entries with the specified text.
def cveSearch(textSearch='', yearStart=0, yearStop=0,
              dataDir=dataDir, dataPrefix=dataPrefix, 
              dataSuffix=dataSuffix, writeJSON=''):

    cveCount = 0
    cveInfo = {}
    cveJSON = {}
    for yr in range(yrStart, yrStop+1):
        dataFile = dataDir + dataPrefix + str(yr) + dataSuffix
        with open(dataFile) as f:
            data = json.load(f)
    
        cveItems = data['CVE_Items']
        for cveLoc in cveItems:
            cveYes = False
            
            cveString = str(cveLoc)
            if (textSearch in cveString):
                cveYes = True
    
            if cveYes:
                cveCount += 1
                cvePublished = cveLoc['publishedDate']
                cveID = cveLoc['cve']['CVE_data_meta']['ID']
                cveInfo[cveCount] = [cveID, cvePublished]
                cveJSON[cveCount] = cveLoc
        
    if writeJSON:
        dataOut = {}
        for key in data.keys():
            if (key == 'CVE_data_type' or
                key == 'CVE_data_format' or
                key == 'CVE_data_timestamp' or
                key == 'CVE_data_version'):
                dataOut[key] = data[key]
            elif (key == 'CVE_data_numberOfCVEs'):
                dataOut[key] = max(cveJSON.keys())
            elif (key == 'CVE_Items'):
                dataOut[key] = list(cveJSON.values())
                
        dataFile = dataDir + writeJSON
        print("Writing JSON FILE: ",dataFile)
        with open(dataFile,'w') as outFile:
            json.dump(dataOut, outFile)
                
    print('Total Found: ', cveCount)
    return cveInfo

# Routine to write out a file with the dates and accumulated numbers
# of CVEs.
def cveSave(cveDict, saveFile='',printSorted=False):
    
    # Pull out the months and years from all of the CVEs.
    yr1 = 9999
    yr2 = -9999
    for i in cveDict.keys():
        yrHere = int(cveDict[i][1][0:4])
        if (yrHere > yr2):
            yr2 = yrHere
        if (yrHere < yr1):
            yr1 = yrHere
    nyrs = yr2-yr1+1 
    
    # Place the CVEs into monthly bins.
    cveSorted = np.zeros((12,nyrs))
    for i in cveDict.keys():
        yrHere = int(cveDict[i][1][0:4])
        monHere = int(cveDict[i][1][5:7])        
        cveSorted[monHere-1,yrHere-yr1] += 1
        
    if printSorted:
        print("CVEs Sorted By Month (rows) and Year (cols)")
        print(cveSorted)
        
    # Create accumulated arrays and write file if requested.
    if saveFile:
        print('Writing File: {}'.format(saveFile))
        fObj = open(saveFile,'w')
        fObj.write("Date, Accum_CVEs\n")
    
    ntime = 12*nyrs
    cvesAccum = np.zeros(ntime)
    timeAccum = np.zeros(ntime)
    cvesCount = 0
    iCount = 0
    for yr in range(nyrs):
        for mon in range(12):
            cvesCount += cveSorted[mon,yr]
            cvesAccum[iCount] = cvesCount
            timeAccum[iCount] = yr + yr1 + (mon+0.5)/12.
            iCount += 1
            
            if saveFile:
                if (mon < 9):
                    mymonString = '0' + str(mon+1)
                else:
                    mymonString = str(mon+1)
                    
                fObj.write("{0}/{1}, {2}\n".format(mymonString,
                                str(yr+yr1), str(int(cvesCount))))
    if saveFile:
        fObj.close()        
            
    return cvesAccum, timeAccum
    
# Routine to plot the vulnerabilities against time.
def cvePlot(vals, time, title='', save=''):
    plt.rc('font', size=13)
    fig, ax = plt.subplots(figsize=(9,5))
    ax.plot(time, vals)
    
    ax.set_title(title)
    ax.set_xlabel('Time')
    ax.set_ylabel('Accumulated CVEs')
    
    if save:
        plt.savefig(save)
    
################################################
# Run the requested searches:    
runSearches = True
if runSearches:
    cveInfo1 = cveSearch(myText1,writeJSON=myJSON1)
    cveAcc1, tAcc1 = cveSave(cveInfo1, mySave1)
    cvePlot(cveAcc1, tAcc1, myTitle1)

    cveInfo2 = cveSearch(myText2,writeJSON=myJSON2)
    cveAcc2, tAcc2 = cveSave(cveInfo2, mySave2)
    cvePlot(cveAcc2, tAcc2, myTitle2)

