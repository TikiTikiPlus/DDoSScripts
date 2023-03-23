import os, time, csv
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
    def __init__(self,startTime, finalTime, ip_dst, port_dst, protocol,byteSize, packetCount, attack, packet):
        self.timeStart = startTime
        self.finalTime = finalTime
        self.ip_dst = ip_dst
        self.port_dst = port_dst
        self.protocol = protocol
        self.byteSize=byteSize
        self.packetCount=packetCount
        self.attack = attack
        self.packetArray=[]
        self.packetArray.append(packet)
flowRecords=[]
flows=[]
packetArray=[]
timestampDifference=0
def main():
    basePath = os.getcwd()
    file = basePath + "\\..\\DDoSAttackData\\MPH.txt"
    matched=False
    try:
        packet=""
        with open(file, "r") as f:
            lines = f.readlines()
            lineNumber = 0
            for line in lines:
                lineNumber+=1
                print(str(lineNumber) + " out of " + str(len(lines)))
                line=line.replace('\n','')
                line = line.split('|')
                if len(line) < 9:
                    matched = False
                    #store a value into an array
                    packet=Packet(line[0],line[1],line[2],line[3],line[4],line[5],line[6],line[7])
                    if len(flows)>0:
                        #check if packets have the same values as the flow records
                        flow1 = Flow(packet.timeStamp, packet.timeStamp, packet.destination_add, packet.destination_port, packet.protocol, packet.bytes,0 , False, packet)
                        len(flows)
                        #Check for the flowrecords
                        for flow in flows:
                            if (((int(flow.timeStart) + 60000)) > int(flow1.timeStart)) and (flow1.ip_dst == flow.ip_dst) and (flow1.port_dst == flow.port_dst) and (flow.protocol == flow1.protocol) and (flow1.byteSize == flow.byteSize):
                                matched = True
                                flow.finalTime = flow1.timeStart
                                flow.packetCount+=1
                                flow.byteSize+=flow1.byteSize
                                flow.packetArray.append(packet)
                                if flow.packetCount == 5:
                                    flow.attack=True
                                break
                        if matched == False:
                            flows.append(flow1)
                    else:
                        flow = Flow(packet.timeStamp, packet.timeStamp, packet.destination_add, packet.destination_port, packet.protocol, packet.bytes, 0, False, packet)
                        flows.append(flow)
                        
                    #check for the same dst ip addresses
        csvFile = open(basePath + "/MPH.csv", 'w', newline='')  
        writer = csv.writer(csvFile)
        for flow in flows:
            data = [flow.timeStart, flow.finalTime, flow.ip_dst, flow.port_dst, flow.protocol, flow.byteSize, flow.packetCount, flow.attack]
            writer.writerow(data)
            for packet in  flow.packetArray:
                writer.writerow([packet.timeStamp, packet.protocol, packet.source_port, packet.destination_add, packet.destination_port, packet.bytes, packet.TTL])
 
        csvFile.close()

                    
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    main()

