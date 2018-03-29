import pyshark


def attack(startingTime, NUMBER_OF_BITS, window, cutoff, MAC_ID, pcapPath):
    pcap = pyshark.FileCapture(pcapPath)
    try:
        outfile = open("out.txt", "a", 0)
    except IOError:
        return "fail"

    with outfile:
        index = 0
        while pcap[index].frame_info.time_epoch < startingTime:
            index += 1
        endingTime = startingTime + window
        result = ""
        while NUMBER_OF_BITS:
            numOfBytes = 0
            while float(pcap[index].frame_info.time_epoch) < endingTime:
                    header = str(pcap[index])
                    if MAC_ID in header:
                        numOfBytes += int(pcap[index].length)
                    index += 1
            endingTime += window
            bitRate = numOfBytes / window
            if bitRate > cutoff:
                result += '1'
            else:
                result += '0'

            if len(result) > 7:
                asInt = int(result, 2)
                asChar = chr(asInt)
                outfile.write(str(asChar))
                print (asChar)
                print (result)
                result = ''
            NUMBER_OF_BITS -= 1
        outfile.close()


##startingTime = 1522316845.937
startingTime = 1522357031.895
window = 5
NUMBER_OF_BITS = 168
cutoff = 50000
MAC_ID = "Destination: ac:2b:6e:b7:0e:c1"
pcapPath = "5sec.pcapng"
"""
pcapPath = pyshark.FileCapture('new2.pcapng')
startingTimenew2 = 1504641903.341627426
startingTime5 = 1522357031.895
startingTime2 = 1522342691.681
window = 2
NUMBER_OF_BITS = 32
cutoff = 450000
MAC_ID = "Destination: ac:2b:6e:b7:0e:c1"
"""
attack(startingTime, NUMBER_OF_BITS, window, cutoff, MAC_ID, pcapPath)
