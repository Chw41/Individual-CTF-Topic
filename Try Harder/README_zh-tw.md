#  Try Harder

## Introduction
在滲透測試或內部滲透評估中，Active Directory（AD）enumeration 是關鍵的步驟。許多資安專業人員在進行 AD enumeration 時，會選擇使用 PowerShell Remoting（WinRM） 來執行遠端指令，但這可能會導致 Kerberos Double-Hop 問題，影響某些 AD enumeration tools 的運作。

相信你讀完 OSCP，不一定會了解為何 RDP（Remote Desktop Protocol）會是更好的選擇，但肯定能找到 Flag 的線索。\
BTW, GenericAll 是 AD 中一種特殊的權限，可能利用於提權. Ex.`stephanie`

💡 Try Harder: [GitHub - Chw41/OffSec-Certification](https://github.com/Chw41/OffSec-Certification)
