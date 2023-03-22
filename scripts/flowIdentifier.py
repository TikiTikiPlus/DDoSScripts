import os
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
    def __init__(self, timeStamp, protocol, src_add, src_port, dst_add, dst_port, bytes, TTL,packetNumber, attack):
        self.timeStamp = timeStamp
        self.protocol = protocol
        self.source_address=src_add
        self.source_port=src_port
        self.destination_add=dst_add
        self.destination_port=dst_port
        self.bytes=bytes
        self.TTL=TTL
        self.packetCount = packetNumber
        self.attack = attack
flowRecords=[]
flow=[]
fts = 0
lts = 0
packetArray=[]
timestampDifference=0
def main():
    file = "/home/ro68/Downloads/MPH/DDoSAttackData/MPH.txt"
    try:
        packet=""
        with open(file, "r") as f:
            lines = f.readlines()
            for line in lines:
                line=line.replace('\n','')
                line = line.split('|')
                if len(line) == 8:
                    #store a value into an array
                    
                    packet=Packet(line[0],line[1],line[2],line[3],line[4],line[5],line[6],line[7])
                    print(packet.timeStamp)
                    if len(packetArray)!=0:
                        if packetArray[0].desination_add.equals(packet.destination_add):
                            if timestampDifference > packet.timeStamp:
                                continue
                            else:

                                packetArray=[]
                    if len(packetArray)==0:
                        timestampDifference=packet.timeStamp + 60000
                    #check for the same dst ip addresses
                    



                    packetArray.append(packet)

                    
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == '__main__':
    main()

