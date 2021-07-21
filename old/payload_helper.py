payload =  b"" # Replace with generated payload.
               # Example: msfvenom -p windows/exec -a x86 --platform Windows CMD=calc.exe EXITFUNC=thread -f python -v payload 

if __name__ == '__main__':
    template = "PAYLOAD[%d] := $%x;\n";

    payload_code = ""

    for index, byte in enumerate(payload):
        payload_code += template % (index, byte)


    print(payload_code)
    print(len(payload))
