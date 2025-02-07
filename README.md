# HawkIOC - Malware Static Analysis Automation Tool

HawkIOC is a Python-based tool designed to automate a large part of the **static analysis** process for malware samples. It extracts important indicators of compromise (IOCs) and generates various hashes to assist in threat intelligence and forensics.

## Features
- **File Type Identification**: Determines the file type and displays magic numbers.
- **Hash Generation**: Computes MD5, SHA256, IMPHASH, and SSDEEP hashes.
- **PE Section Hashing**: Generates SHA256 and MD5 hashes for each PE section.
- **String Extraction**: Extracts ASCII & Unicode strings and saves them to `<filename>_strings.txt`.
- **Entropy Calculation**: Computes file and PE section entropy to detect packing.
- **UPX Detection & Unpacking**: Identifies UPX-packed files and attempts to unpack them.

## Installation

### **Clone the Repository**

```bash
git clone https://github.com/yourusername/HawkIOC.git
cd HawkIOC
```

### **Dependencies**

Ensure you have the following installed:
```bash
sudo apt update && sudo apt install -y yara upx ssdeep python3-pip
pip install -r requirements.txt
```

## Usage

Run the tool with:
```bash
python3 hawkioc.py -f <malware_sample> [--yara rules.yar]
```
Example:
```bash
python3 hawkioc.py -f sample.exe
```

### **Output Files**
- Extracted strings: `<filename>_strings.txt`
- Unpacked binary (if applicable): `<filename>_unpacked.exe`

## Example Output
```
python hawkioc.py -f apple.exe                                                                                                                                   ✔  test  
    __  __               __   ____      ______
   / / / /___ __      __/ /__/  _/___  / ____/
  / /_/ / __ `/ | /| / / //_// // __ \/ /     
 / __  / /_/ /| |/ |/ / ,< _/ // /_/ / /___   
/_/ /_/\__,_/ |__/|__/_/|_/___/\____/\____/   
                                              


Created by: pnasis
Version: v1.0

[INFO] Analyzing: apple.exe

==================================================
                [File Information]
==================================================
[INFO] File Type: PE32+ executable for MS Windows 5.02 (GUI), x86-64, 6 sections
[INFO] Magic Numbers: 4D5A900003000000

==================================================
                [File Hashes]
==================================================
[INFO] MD5: 1c7243c8f3586b799a5f9a2e4200aa92
[INFO] SHA256: f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e

==================================================
                [PE File Analysis]
==================================================
[INFO] IMPHASH: 475b069fec5e5868caeb7d4d89236c89
[INFO] Section: .text, MD5: bbd3af727b760f43f79949ed12967f15, SHA256: ea37fa217219f7386ca98011dda7fac1f7f7cc24895cf9273d49640b63b01fff
[INFO] Section: .rdata, MD5: 17f740269d4d7b5a4dba2dcf5f974db6, SHA256: 66243010815564074a14e8cb5afa99ea9cc536112be06d94772b43ca02aba5cc
[INFO] Section: .data, MD5: 2e35bbdf7154182a22115a6f25bfa771, SHA256: 1649f5ba302336d40f72b66a60bea442e80cb7d203564945df36b3c37dd31b0e
[INFO] Section: .pdata, MD5: 41d59b361c2388908534d43ad9beeafc, SHA256: 8bb63485bae4c760978139368ffd882815d116d92a830c3e019355c64c75f4b0
[INFO] Section: .rsrc, MD5: 60dbb5e97fab0b4434173e100d16967c, SHA256: a10593dad8bf8d9dbcb2ba3de64444e8dc694d072885bcfde78782d785120388
[INFO] Section: .reloc, MD5: 839270e9b89f3de10367cb764b52800f, SHA256: 58cd917c1aaa4463384d70f2e8d0e60edcfed2bb8640a086fa4428b627aa3226

==================================================
                [Fuzzy Hashing (SSDEEP)]
==================================================
[INFO] SSDEEP: 1536:b6sMD3H8V3jsUnHLiREsTbDV/48OO4vh47483gLi9+LSG:b6srVzJiRrTHVORe75g4+LS

==================================================
                [Entropy Analysis]
==================================================
[INFO] File Entropy: 5.9184

[INFO] PE Section Entropy:
    * .text: 6.3495
    * .rdata: 4.7603
    * .data: 1.9729
    * .pdata: 4.5047
    * .rsrc: 1.8680
    * .reloc: 2.5550

[INFO] Entropy levels suggest the file is not packed.

==================================================
                [Extracting Strings]
==================================================
[INFO] Extracted 1709 strings.
[INFO] Strings saved to: apple_strings.txt
[INFO] Extracting PE Resources...
[INFO] Found resource type: 88

==================================================
                [Import Functions]
==================================================
[INFO] Extracting Import Functions...
[INFO] Imported Functions:
  - DLL: ADVAPI32.dll
    * RegSetValueExA
    * RegOpenKeyExA
    * RegDeleteValueA
    * RegFlushKey
    * RegCloseKey
    * CryptAcquireContextW
    * CryptDeriveKey
    * CryptReleaseContext
    * CryptEncrypt
    * CryptCreateHash
    * CryptDestroyKey
    * CryptDecrypt
    * CryptDestroyHash
    * CryptHashData
  - DLL: WININET.dll
    * HttpSendRequestA
    * InternetQueryDataAvailable
    * InternetReadFile
    * InternetCloseHandle
    * HttpQueryInfoA
    * InternetConnectA
    * InternetOpenA
    * HttpOpenRequestA
    * InternetSetOptionA
  - DLL: WS2_32.dll
    * gethostbyname
    * WSACleanup
    * WSAStartup
    * inet_ntoa
    * gethostname
  - DLL: KERNEL32.dll
    * CreateFileW
    * HeapSize
    * WriteConsoleW
    * SetStdHandle
    * LoadLibraryW
    * GetStringTypeW
    * LCMapStringW
    * LeaveCriticalSection
    * EnterCriticalSection
    * CreateFileA
    * FindResourceA
    * LoadResource
    * HeapAlloc
    * HeapFree
    * GetProcessHeap
    * WriteFile
    * SizeofResource
    * GetLastError
    * LockResource
    * GetModuleHandleA
    * CloseHandle
    * GetComputerNameA
    * HeapReAlloc
    * MoveFileExA
    * WaitForSingleObject
    * SetEvent
    * GetModuleHandleW
    * GetSystemWow64DirectoryA
    * CreateProcessA
    * GetSystemDirectoryA
    * GetEnvironmentVariableA
    * CopyFileA
    * CreateEventW
    * GetModuleFileNameA
    * DeleteFileA
    * GetFileSize
    * ReadFile
    * WideCharToMultiByte
    * GetProcAddress
    * GetTempFileNameA
    * GetTempPathA
    * FlushFileBuffers
    * GetConsoleMode
    * GetCommandLineW
    * GetStartupInfoW
    * TerminateProcess
    * GetCurrentProcess
    * UnhandledExceptionFilter
    * SetUnhandledExceptionFilter
    * IsDebuggerPresent
    * RtlVirtualUnwind
    * RtlLookupFunctionEntry
    * RtlCaptureContext
    * EncodePointer
    * DecodePointer
    * GetCPInfo
    * GetACP
    * GetOEMCP
    * IsValidCodePage
    * FlsGetValue
    * FlsSetValue
    * FlsFree
    * SetLastError
    * GetCurrentThreadId
    * FlsAlloc
    * ExitProcess
    * GetStdHandle
    * GetModuleFileNameW
    * RtlUnwindEx
    * FreeEnvironmentStringsW
    * GetEnvironmentStringsW
    * SetHandleCount
    * InitializeCriticalSectionAndSpinCount
    * GetFileType
    * DeleteCriticalSection
    * HeapSetInformation
    * GetVersion
    * HeapCreate
    * QueryPerformanceCounter
    * GetTickCount
    * GetCurrentProcessId
    * GetSystemTimeAsFileTime
    * Sleep
    * MultiByteToWideChar
    * SetFilePointer
    * GetConsoleCP
  - DLL: USER32.dll
    * GetDC

==================================================
                [Suspicious API Calls]
==================================================
[INFO] Checking for Suspicious API Calls...
[WARNING] Suspicious API Found: RegSetValueExA
[WARNING] Suspicious API Found: RegOpenKeyExA
[WARNING] Suspicious API Found: InternetReadFile
[WARNING] Suspicious API Found: InternetCloseHandle
[WARNING] Suspicious API Found: CreateFileA
[WARNING] Suspicious API Found: CloseHandle
[WARNING] Suspicious API Found: GetComputerNameA
[WARNING] Suspicious API Found: CreateProcessA

==================================================
                [XOR-encoded strings Analysis]
==================================================
[INFO] Checking for XOR-encoded strings...
[ALERT] Possible XOR-encoded strings found with key 32!

==================================================
                [Entropy Visualization]
==================================================
[INFO] Generating entropy visualization...

[INFO] Analysis completed!

```

## Disclaimer

This tool is for **educational and research purposes only**. Do not use it for unethical activities.

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for new features, bug fixes, or documentation improvements.
