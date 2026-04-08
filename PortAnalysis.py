import Portscanner as ps
import sys

# This tool is provided for educational purposes only, including network security learning, CTF competitions, and authorized penetration testing.
# Unauthorized use against any system is strictly prohibited. Users must comply with applicable local laws and regulations.
# The author assumes no responsibility for any misuse or illegal activity.

class PortAnalysis:
    PORT_SAFE_GUIDE_BILINGUAL = {
        21: {
            'zh': 'FTP服务 - 建议禁用匿名登录，使用SFTP替代',
            'en': 'FTP service - It is recommended to disable anonymous login and use SFTP instead.'
        },
        22: {
            'zh': 'SSH服务 - 建议使用密钥登录，关闭密码认证',
            'en': 'SSH service - It is recommended to use key-based login and disable password authentication.'
        },
        23: {
            'zh': 'Telnet服务 - 明文传输，高危！建议立即关闭',
            'en': 'Telnet service - Plain text transmission, high risk! It is recommended to disable it immediately.'
        },
        53: {
            'zh': 'DNS服务 - 建议开启DNSSEC防止劫持',
            'en': 'DNS service - It is recommended to enable DNSSEC to prevent hijacking.'
        },
        80: {
            'zh': 'HTTP服务 - 建议升级为HTTPS(443)加密传输',
            'en': 'HTTP service - It is recommended to upgrade to HTTPS (port 443) for encrypted transmission.'
        },
        443: {
            'zh': 'HTTPS服务 - 安全加密，建议保持开启',
            'en': 'HTTPS service - Secure encryption, it is recommended to keep it enabled.'
        },
        445: {
            'zh': 'SMB服务 - 高危端口！建议关闭公网访问，及时打补丁',
            'en': 'SMB service - High-risk port! It is recommended to disable public access and apply patches promptly.'
        },
        3389: {
            'zh': 'RDP远程桌面 - 建议限制IP访问，开启强密码',
            'en': 'RDP remote desktop - It is recommended to restrict IP access and enforce strong passwords.'
        },
        135: {
            'zh': 'RPC服务 - Windows系统端口，建议防火墙限制访问',
            'en': 'RPC service - Windows system port, it is recommended to restrict access via firewall.'
        }
    }

    def __init__(self,result,method):
        self.result = result
        self.method = method

    def list_open_ports(self):
        print('=' * 50)
        print(f'Scan method: {self.method}')
        print(f'Number of open ports: {len(self.result)}')
        print('=' * 50)

        if not self.result:
            print('No open ports')
            return
        for port , info in self.result.items():
            print(f'Port: {port}\tService: {info["service"]}\tVersion: {info["version"]}')

    def security_open_ports(self):
        print('=' * 50)
        print('security advice')
        print('=' * 50)

        for port in self.result:
            port_num = int(port)
            guide = self.PORT_SAFE_GUIDE_BILINGUAL[port_num]
            print(f'Port : {port_num}')
            print(f'中文 : {guide["zh"]}')
            print(f'English : {guide["en"]}')
            print('=' * 50)


if __name__ == '__main__':
    # Compliance Confirmation
    confirm = input('Confirm you are authorized to scan (yes/y): ')
    if confirm.lower() not in ['yes', 'y']:
        print('Aborted. Only authorized testing is allowed.')
        sys.exit()

    # User Input
    ip = input('Target IP: ').strip()
    ports = input('Ports (1-65535): ').strip()
    scan_type = input('Scan type (S/T/U): ').strip().upper()
    speed = input('Speed (1-5, 1=slowest,5=fastest): ').strip()

    # Execute Scan
    try:
        scanner = ps.PortScanner(ip, ports, speed)
        scan_method = getattr(scanner, f'scan_s{scan_type}')
        scan_result = scan_method()
    except AttributeError:
        print(f'[ERROR] Invalid scan type: {scan_type}. Only S/T/U allowed.')
        sys.exit(1)
    except Exception as e:
        print(f'[ERROR] Scan failed: {e}')
        sys.exit(1)

    #  Run Analysis
    analyzer = PortAnalysis(scan_result, f'scan_s{scan_type}')
    analyzer.list_open_ports()
    analyzer.security_open_ports()



