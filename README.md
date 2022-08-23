# breakcyserver

<br/>Full post in: [https://waawaa.github.io/](https://waawaa.github.io/en/Bypass-PPL-Using-Process-Explorer/)

<br/> 1. Kill EDR services by killing all the opened handles of the EDR process.
<br/> 2. Bypass PPL by abussing some Process Explorer drivers functionalities.
<br/> 3. Bypass ObRegisterCallbacks implementation by abussing Process Explorer driver functionalities.

<br/>PS: Added Implementation to load the driver manually without ProcessExplorer.  
LoadDriver.exe /LOAD  
LoadDriver.exe /UNLOAD  

Another evasion technique to load the driver without the victim noticing could be by  
abusing normal procexp.exe features  (EDRs and XDRs might notice an unsigned EXE loading a driver and adding reg key)  
```  
.\procexp64.exe -accepteula /t  
```  
