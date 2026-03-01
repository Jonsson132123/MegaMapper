# MegaMapper
MegaMapper är ett verktyg som skannar nätverk efter hosts, portar och tar fram information om tjänster som körs.
<br>
<br>
installation:
MegaMapper använder python modulen scapy för arp requests. För att MegaMapper ska funka måste scapy installeras via kommandot pip install scapy. 
<br>
<br>
Scapy kräver även att Npcap/libpcap är installerat beroende på OS.<br>
För Windows installera npcap, länk till npcap: https://npcap.com/#download <br>
För Linux installera libpcap, ofta förinstallerat, annars sudo apt install libpcap-dev <br>
För Mac är libpcap oftast förinstallerat via Xcode tools. <br> 
<br>
Skriven av Albin Jonsson 2026-03-01
