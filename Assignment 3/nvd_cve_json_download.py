from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile

timeStart = 2002
timeStop = 2020
search_time_duration=list(range(timeStart, timeStop+1))

for year in search_time_duration:
    url="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" +str(year)+ ".json.zip"
    print("Downloading NVD feed data for year "+str(year)+ "  from the following link...")
    print(url)
    
    with urlopen(url) as zipresp:
        with ZipFile(BytesIO(zipresp.read())) as zfile:
            zfile.extractall()

	
