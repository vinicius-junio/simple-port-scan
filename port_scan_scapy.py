import random
from scapy.all import ICMP, IP, sr1, TCP, sr
import sys

message = ["How to Use: python [script] [target] [initialport] [endport]","\nExample: python port_scan_scapy.py 127.0.0.1 80 65535"]

class ValidateArgs:
  #
  # Validate Args
  #
  def __init__(self):
    if (len(sys.argv) != 4):
      print(message[0],message[1])
      sys.exit()

class RandomPorts:
  #
  # Random Ports
  #
  def random_port(self) -> int:
    src_port = random.randint(1025,65534)
    return src_port
  
class Messages:
  #
  # Messages
  #
  def message_filtered(self, target: str, destination_port: int) -> None:
    print(f"[*] {target}:{destination_port} is filtered.")
  
  def message_open(self, target: str, destination_port: int) -> None:
     print(f"[+] {target}: {destination_port} is open!")

  def message_closed(self, target: str, destination_port: int) -> None:
     print(f"[-] {target}: {destination_port} is closed!")

class PortScanScapy:
  #
  # Port Scanning
  #
  def __init__(self,target: str, initialport: int, endport: int):
    self.dst_port = list(range(initialport, endport + 1))
    self.target = target
    self.initialport = initialport
    self.endport = endport

  def port_scan_initializer(self):
    for destination_port in self.dst_port:
      src_port = RandomPorts().random_port()
      response = sr1(
        IP(dst=self.target)/TCP(sport=src_port,dport=destination_port,flags="S"),timeout=1,
        verbose=0,
      )
      if(response is None):
        Messages().message_filtered(self.target, destination_port)
      elif(response.haslayer(TCP)):
        if(response.getlayer(TCP).flags == 0x12):
          send_rst = sr(
            IP(dst=self.target)/TCP(sport=src_port,dport=destination_port,flags='R'),
            timeout=1,
            verbose=0,
          )
          Messages().message_open(self.target, destination_port)
        elif (response.getlayer(TCP).flags == 0x14):
          Messages().message_closed(self.target, destination_port)
      elif(response.haslayer(ICMP)):
        if(int(response.getlayer(ICMP).type) == 3 and
           int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]):
           Messages().message_filtered(self.target, destination_port)

def main():
  ValidateArgs()
  _target = sys.argv[1]
  _initialport = int(sys.argv[2])
  _endport = int(sys.argv[3])

  portScan = PortScanScapy(_target,_initialport,_endport)
  portScan.port_scan_initializer()
    
if __name__ == '__main__':
  main()