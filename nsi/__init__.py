# Because of the obnoxious cryptography warning about TripleDES. :(
import warnings
warnings.filterwarnings(action='ignore', module='.*paramiko.*')
warnings.filterwarnings(action='ignore', module='.*scapy.*')

__version__ = '0.0.1'