import nmap
import sys
import random
# This tool is provided for educational purposes only, including network security learning, CTF competitions, and authorized penetration testing.
# Unauthorized use against any system is strictly prohibited. Users must comply with applicable local laws and regulations.
# The author assumes no responsibility for any misuse or illegal activity.

class PortScanner:
    def __init__(self,ip,ports,speed):
        self.ip = ip.strip()
        self.ports = ports.strip()
        self.speed = speed.strip()
        self.nm = nmap.PortScanner()

    def scan_sS(self):     #need root  SYN
        try:
            self.nm.scan(
                hosts=self.ip,
                ports=self.ports,
                arguments=f'-sS -sV -f -T{self.speed} --open --min-parallelism 1024 --data-length {random.randint(8,32)} -Pn'
            )
        except Exception as e:
            print(f'scan failed: {e}')
            return {}
        return self._parse_result('tcp')

    def scan_sT(self):    #no root,slower,easy to detect    TCP
        try:
            self.nm.scan(
                hosts=self.ip,
                ports=self.ports,
                arguments=f'-sT -sV -f -T{self.speed} --open --min-parallelism 1024 --data-length {random.randint(8,32)} -Pn'
            )
        except Exception as e:
            print(f'scan failed: {e}')
            return {}
        return self._parse_result('tcp')

    def scan_sU(self):    #need root    UDP
        try:
            self.nm.scan(
                hosts=self.ip,
                ports=self.ports,
                arguments=f'-sU -sV -f -T{self.speed} --open --min-parallelism 1024 --data-length {random.randint(8,32)} -Pn'
            )
        except Exception as e:
            print(f'scan failed: {e}')
            return {}
        return self._parse_result('udp')

    def _parse_result(self,protocol):
        open_ports = {}
        for host in self.nm.all_hosts():
            for port,info in self.nm[self.ip][protocol].items():
                if info['state'] == 'open':
                    open_ports[port] = {
                        'service': info.get('name','unknown'),
                        'version': info.get('version','unknown'),
                    }
        return open_ports


if __name__ == '__main__':
    confirm = input('Please confirm the legality of your actions. The author bears no responsibility!(yes/no)or(y/n): ')
    if confirm == 'yes'or confirm =='y':
        print('It is running\n')
    else:
        print('Aborted by user. Only authorized testing is allowed.')
        sys.exit()


    ip = input('input ip address: ').strip()
    ports = input('input ports: ').strip()
    way = input('input way,like S or T or U : ').strip().upper()
    speed = input('input scan speed(1~5,1 slowest,5 fastest): ').strip()


    scanner = PortScanner(ip,ports,speed)


    result = getattr(scanner,f'scan_s{way}')
    print(result)