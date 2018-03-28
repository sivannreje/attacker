import pyshark


def attack(startingTime, NUMBER_OF_BITS, window, cutoff, MAC_ID, pcapPath):
    packets = []
    index = 0
    message = ""
    index = 0
    while pcapPath[index].frame_info.time_epoch < startingTime:
        index += 1
    endingTime = startingTime + window
    result = ""
    while NUMBER_OF_BITS:
        numOfBytes = 0
        while float(pcapPath[index].frame_info.time_epoch) < endingTime:
                header = str(pcapPath[index])
                if MAC_ID in header:
                    numOfBytes += int(pcapPath[index].length)
                index += 1
        endingTime += window
        bitRate = numOfBytes / window
        if bitRate > cutoff:
            result += '1'
        else:
            result += '0'

        if len(result) > 7:
            a = int(result, 2)
            b = chr(a)
            message += b
            print (message)
            print (result)
            result = ''
        NUMBER_OF_BITS -= 1

    with open("out.txt", "a") as outfile:
        outfile.write(message)

"""
pcapPath = pyshark.FileCapture('new2.pcapng')
startingTime = 1522165827.107
window = 2
NUMBER_OF_BITS = 168
cutoff = 80000
MAC_ID = "Destination: ac:2b:6e:b7:0e:c1"
"""
pcapPath = pyshark.FileCapture('mystery.pcapng')
startingTime = 1504641903.341627426
window = 2
NUMBER_OF_BITS = 32
cutoff = 450000
MAC_ID = "Destination: cc:20:e8:17:4d:ab"

attack(startingTime, NUMBER_OF_BITS, window, cutoff, MAC_ID, pcapPath)
