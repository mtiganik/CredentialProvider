
This program is modified version, taken from:
github.com/pauldotknopf/WindowsSDK7-Samples/tree/master/security/credentialproviders/samplecredentialprovider

How to run this:
--------------------------------
Once you have built the project, copy autologincredentialprovider.dll to the System32 directory
and run Register.reg from an elevated command prompt. The credential should appear the next
time a logon is invoked (such as when logging off or rebooting the machine).

What this sample demonstrates
-----------------------------
This sample demonstrates simple password based log on and unlock behavior.  It also shows how to construct
a simple user tile and handle the user interaction with that tile.

