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
    def __init__(self,ip_dst, port_dst, protocol,byteSize):
        self.ip_dst = ip_dst
        self.port_dst = port_dst
        self.protocol = protocol
        self.byteSize=byteSize
class FlowRecord:
    def __init__(self, timestamp, flow, packetCount, attack):
        self.startTime = timestamp
        self.flow=flow
        self.packetCount = packetCount
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
                    #store a value into an array
                    
                    packet=Packet(line[0],line[1],line[2],line[3],line[4],line[5],line[6],line[7])
                    len("lowRecords")
                    if len(flowRecords)>0:
                        #check if packets have the same values as the flow records
                        flow1 = Flow(packet.destination_add, packet.destination_port, packet.protocol, packet.bytes)
                        len(flowRecords)
                        for flow in flowRecords:
                            print("flow " + str(flow.ip_dst) + " " + str(flow.port_dst) + " " + str(flow.protocol) + " " + str(flow.byteSize))
                            print("flow1 " + str(flow1.ip_dst) + " " + str(flow1.port_dst) + " " + str(flow1.protocol) + " " + str(flow1.byteSize))
                            time.sleep(3)                            
                            if (flow1.ip_dst == flow.ip_dst) and (flow1.port_dst == flow.port_dst) and (flow.protocol == flow.protocol) and (flow1.byteSize == flow.byteSize):
                                print(flow1.ip_dst + " " + flow1.port_dst + " " + flow1.protocol + " " + flow1.byteSize)
                                matched = True
                                print(matched)
                                break
                        if matched == False:
                            flowRecords.append(flow1)
                    else:
                        flowRecords.append(Flow(packet.destination_add, packet.destination_port, packet.protocol, packet.bytes))
                    #check for the same dst ip addresses
        for flow in flowRecords:
            print(str(flow.ip_dst) + " " + str(flow.port_dst) + " " + str(flow.protocol) + " " + str(flow.byteSize))

                    
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    main()

