import os, time, csv, sys
class Packet:
    def __init__(self, timeStamp, protocol, src_add, src_port, dst_add, dst_port, bytes, TTL):
        self.timeStamp = timeStamp
        self.protocol = protocol
        self.source_address=src_add
        self.source_port=src_port
        self.destination_add=dst_add
        self.destination_port=dst_port
        self.bytes=bytes
        self.TTL=TTL
class Flow:
    def __init__(self,startTime, finalTime, ip_source, ip_dst, port_dst, protocol,byteSize, packetCount, attack):
        self.timeStart = startTime
        self.finalTime = finalTime
        self.ip_source = ip_source
        self.ip_dst = ip_dst
        self.port_dst = port_dst
        self.protocol = protocol
        self.byteSize=byteSize
        self.packetCount=packetCount
        self.attack = attack
flowRecords=[]
flows=[]
packetArray=[]
timestampDifference=0

def main(inputFile, outputFile):
    matched=False
    try:
        packet=""
        with open(inputFile, "r") as f:
            lines = f.readlines()
            lineNumber = 0
            for line in lines:
                lineNumber+=1
                print(str(lineNumber) + " out of " + str(len(lines)))
                line=line.replace('\n','')
                line = line.split('|')
                if len(line) == 8 and '#' not in line[0]:
                    matched = False
                    #store a value into an array
                    packet=Packet(line[0],line[1],line[2],line[3],line[4],line[5],line[6],line[7])
                    if len(flows)>0:
                        #check if packets have the same values as the flow records
                        flow1 = Flow(packet.timeStamp, packet.timeStamp, packet.source_address,packet.destination_add,  packet.destination_port, packet.protocol, packet.bytes,1, False)
                        len(flows)
                        #Check for the flowrecords
                        for flow in flows:
                            if (((int(flow.finalTime) + 60000000)) > int(flow1.timeStart)) and (flow1.ip_source == flow.ip_source) and (flow1.ip_dst == flow.ip_dst) and (flow1.port_dst == flow.port_dst) and (flow.protocol == flow1.protocol):
                                matched = True
                                flow.finalTime = flow1.timeStart
                                flow.packetCount+=1
                                flow.byteSize= int(flow.byteSize)+int(flow1.byteSize)
                                if flow.packetCount == 5:
                                    flow.attack=True
                                break
                        if matched == False:
                            flows.append(flow1)
                    else:
                        flow = Flow(packet.timeStamp, packet.timeStamp, packet.source_address,packet.destination_add, packet.destination_port, packet.protocol, packet.bytes, 1, False)
                        flows.append(flow)
                        
                    #check for the same dst ip addresses
        textFile = open(outputFile, 'w')  
        header="# Start time|End time|Protocol|Victim IP|HoneyPot IP|Amplifier Protocol|Byte size|Packet count|Attack Count \n"
        textFile.write(header)
        attackArray = []
        attackCount = 0
        previousLine = ""
        previousFlow=""
        for flow in flows:
            if(flow.attack==True):
                if(flow.port_dst=="19"):
                    flow.port_dst="NTP"
                elif(flow.port_dst=="11211"):
                    flow.port_dst="CHARGEN"
                elif(flow.port_dst=="53"):
                    flow.port_dst="DNS"
                elif(flow.port_dst=="17"):
                    flow.port_dst="QOTD"
                flow.timeStart=int(int(flow.timeStart)/1000000)
                flow.finalTime=int(int(flow.finalTime)/1000000)
                if str(previousFlow) == str(flow.ip_source):
                    attackCount=attackCount
                else:
                    attackCount+=1
                data = str(flow.timeStart)+"|"+ str(flow.finalTime)+"|"+str(flow.protocol)+"|"+ str(flow.ip_source) +"|"+ str(flow.ip_dst)+"|"+ str(flow.port_dst)+ "|"+str(flow.byteSize)+ "|"+ str(flow.packetCount)+ "|"+ str(attackCount) + " \n"
                textFile.write(data)
                
                previousFlow=flow.ip_source

            # packetHeader=["Timestamp", "Protocol", "Source IP","Source port", "Destination IP", "Destination Port", "Bytes", "TTL"]
            # writer.writerow(packetHeader)
            # for packet in  flow.packetArray:
            #     writer.writerow([packet.timeStamp, packet.protocol, packet.source_address , packet.source_port, packet.destination_add, packet.destination_port, packet.bytes, packet.TTL])
        textFile.close()

                    
    except Exception as e:
        print(f"An error occurred: {str(e)}")
if __name__ == '__main__':
    for i, arg in enumerate(sys.argv):
        if arg == '-i':
            input_file = sys.argv[i+1]
        elif arg == '-o':
            output_file = sys.argv[i+1]
    main(input_file, output_file)

