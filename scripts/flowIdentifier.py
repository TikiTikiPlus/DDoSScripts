import os, time
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
    def __init__(self,timestamp, ip_dst, port_dst, protocol,byteSize, packetCount, attack):
        self.timestamp = timestamp
        self.ip_dst = ip_dst
        self.port_dst = port_dst
        self.protocol = protocol
        self.byteSize=byteSize
        self.packetCount=packetCount
        self.attack = attack
flowRecords=[]
flows=[]
fts = 0
lts = 0
packetArray=[]
timestampDifference=0
def main():
    file = "/home/ro68/Downloads/MPH/DDoSAttackData/MPH.txt"
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
                        flow1 = Flow(packet.timeStamp, packet.destination_add, packet.destination_port, packet.protocol, packet.bytes,0 , False)
                        len(flows)
                        #Check for the flowrecords
                        for flow in flows:
                            if (((int(flow.timestamp) + 60000)) > int(flow1.timestamp)) and (flow1.ip_dst == flow.ip_dst) and (flow1.port_dst == flow.port_dst) and (flow.protocol == flow1.protocol) and (flow1.byteSize == flow.byteSize):
                                matched = True
                                flow.packetCount+=1
                                if flow.packetCount == 5:
                                    flow.attack=True
                                break
                        if matched == False:
                            print(matched)
                            flows.append(flow1)
                    else:
                        flow = Flow(packet.timeStamp,packet.destination_add, packet.destination_port, packet.protocol, packet.bytes, 0, False)
                        flows.append(flow)
                        
                    #check for the same dst ip addresses
        for flow in flows:
            print(str(flow.ip_dst) + " " + str(flow.port_dst) + " " + str(flow.protocol) + " " + str(flow.byteSize) + " " + str(flow.packetCount) +  " " +str(flow.attack))

                    
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    main()

