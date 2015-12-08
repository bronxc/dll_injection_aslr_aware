import ctypes
import os
import sys

def inject_dll(dllpath, pid):
    shellcode = bytearray("\x56"                          # PUSH ESI
                          "\x57"                          # PUSH EDI
                          "\xFC"                          # CLD                          
                          "\x6A\x30"                      # PUSH 30h
                          "\x5E"                          # POP ESI
                          "\x64\xAD"                      # LODS DWORD PTR FS:[ESI]
                          "\x89\xC2"                      # MOV EDX, EAX
                          "\x8B\x52\x0C"                  # MOV EDX, DWORD PTR DS:[EDX+0Ch]
                          "\x8B\x52\x14"                  # MOV EDX, DWORD PTR DS:[EDX+14h]
                                                          # NEXT_MODULE:
                          "\x8B\x72\x28"                  # MOV ESI, DWORD PTR DS:[EDX+28h]
                          "\xB9\x18\x00\x00\x00"          # MOV ECX, 18h
                          "\x31\xFF"                      # XOR EDI, EDI
                                                          # NEXT_CHAR:
                          "\x31\xC0"                      # XOR EAX, EAX
                          "\xAC"                          # LODSB
                          "\x3C\x61"                      # CMP AL, 'a'
                          "\x7C\x02"                      # JL SHORT ALREADY_UPPER_CASE
                          "\x2C\x20"                      # SUB AL, 20h
                                                          # ALREADY_UPPER:
                          "\xC1\xCF\x0D"                  # ROR EDI, 0Dh
                          "\x01\xC7"                      # ADD EDI, EAX
                          "\xE2\xF0"                      # LOOP NEXT_CHAR
                          "\x81\xFF\x5B\xBC\x4A\x6A"      # CMP EDI, 6A4ABC5Bh
                          "\x8B\x42\x10"                  # MOV EAX, DWORD PTR DS:[EDX+10h]
                          "\x8B\x12"                      # MOV EDX, DWORD PTR DS:[EDX]
                          "\x75\xD9"                      # JNZ SHORT NEXT_MODULE
                          "\x5F"                          # POP EDI
                          "\x5E"                          # POP ESI
                          "\x89\xC2"                      # MOV EDX, EAX
                          "\xE8\x00\x00\x00\x00"          # CALL DELTA
                                                          # DELTA:
                          "\x5D"                          # POP EBP
                          "\x89\xD3"                      # MOV EBX, EDX
                          "\x8B\x53\x3C"                  # MOV EDX, DWORD PTR DS:[EBX+3Ch]
                          "\x01\xDA"                      # ADD EDX, EBX
                          "\x8B\x52\x78"                  # MOV EDX, DWORD PTR DS:[EDX+78h]
                          "\x01\xDA"                      # ADD EDX, EBX
                          "\x8B\x72\x20"                  # MOV ESI, DWORD PTR DS:[EDX+20h]
                          "\x01\xDE"                      # ADD ESI, EBX
                          "\x31\xC9"                      # XOR ECX, ECX
                                                          # FIND_GET_PROC_ADDR:
                          "\x41"                          # INC ECX
                          "\xAD"                          # LODSD
                          "\x01\xD8"                      # ADD EAX, EBX
                          "\x81\x38\x47\x65\x74\x50"      # CMP DWORD PTR DS:[EAX], "GetP"
                          "\x75\xF4"                      # JNZ FIND_GET_PROC_ADDR
                          "\x81\x78\x04\x72\x6F\x63\x41"  # CMP DWORD PTR DS:[EAX+4], "rocA"
                          "\x75\xEB"                      # JNZ FIND_GET_PROC_ADDR
                          "\x81\x78\x08\x64\x64\x72\x65"  # CMP DWORD PTR DS:[EAX+8], "ddre"
                          "\x75\xE2"                      # JNZ FIND_GET_PROC_ADDR
                          "\x66\x81\x78\x0C\x73\x73"      # CMP WORD PTR DS:[EAX+C], "ss"
                          "\x75\xDA"                      # JNZ FIND_GET_PROC_ADDR
                          "\x8B\x72\x24"                  # MOV ESI, DWORD PTR DS:[EDX+24h]
                          "\x01\xDE"                      # ADD ESI, EBX
                          "\x0F\xB7\x0C\x4E"              # MOVZX ECX, WORD PTR DS:[ESI+ECX*2]
                          "\x49"                          # DEC ECX
                          "\x8B\x72\x1C"                  # MOV ESI, DWORD PTR DS:[EDX+1Ch]
                          "\x01\xDE"                      # ADD ESI, EBX
                          "\x8B\x14\x8E"                  # MOV EDX, DWORD PTR DS:[ESI+ECX*4]
                          "\x01\xDA"                      # ADD EDX, EBX
                          "\x89\x95\x8D\x00\x00\x00"      # MOV DWORD PTR SS:[EBP+8Dh], EDX
                          "\x8D\x75\x7C"                  # LEA ESI, DWORD PTR SS:[EBP+7Ch]
                          "\x8D\xBD\x89\x00\x00\x00"      # LEA EDI, DWORD PTR SS:[EBP+89h]
                          "\x56"                          # PUSH ESI
                          "\x57"                          # PUSH EDI
                          "\x51"                          # PUSH ECX
                          "\x53"                          # PUSH EBX
                          "\x56"                          # PUSH ESI
                          "\x53"                          # PUSH EBX
                          "\xFF\x95\x8D\x00\x00\x00"      # CALL DWORD PTR SS:[EBP+8Dh]
                          "\x5B"                          # POP EBX
                          "\x59"                          # POP ECX
                          "\x5F"                          # POP EDI
                          "\x5E"                          # POP ESI
                          "\xAB"                          # STOSD
                          "\x8D\x85\x91\x00\x00\x00"      # LEA, DWORD PTR SS:[EBP+91h]
                          "\x50"                          # PUSH EAX
                          "\xFF\x95\x89\x00\x00\x00"      # CALL DWORD PTR SS:[EBP+89h]
                          "\xC3"                          # RET
                          "\x4C\x6F\x61\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00" # DB "LoadLibraryA", 0
                          "\x00\x00\x00\x00"              # DD 0
                          "\x00\x00\x00\x00")             # DD 0
    ret = False
    PROCESS_ALL_ACCESS = (0x000F0000L|0x00100000L|0xFFF)
    proc_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, None, pid)
    if proc_handle is not None:
        MEM_COMMIT = 0x00001000
        MEM_RESERVE = 0x00002000
        PAGE_EXECUTE_READWRITE = 0x40
        temp_buffer = shellcode + ctypes.create_string_buffer(dllpath).raw
        alloc_address = ctypes.windll.kernel32.VirtualAllocEx(proc_handle, None,
                                                              len(temp_buffer), MEM_RESERVE|MEM_COMMIT,
                                                              PAGE_EXECUTE_READWRITE)
        if alloc_address is not None:
            c_buffer = (ctypes.c_char * len(temp_buffer)).from_buffer(temp_buffer)
            if ctypes.windll.kernel32.WriteProcessMemory(proc_handle, alloc_address, c_buffer, len(temp_buffer), None):
                thread = ctypes.windll.kernel32.CreateRemoteThread(proc_handle, None, 0, alloc_address, None, 0, None)
                if thread is not None:
                    INFINITE = 0xFFFFFFFF
                    ctypes.windll.kernel32.WaitForSingleObject(thread, INFINITE)
                    MEM_RELEASE = 0x8000
                    if ctypes.windll.kernel32.VirtualFreeEx(proc_handle, alloc_address, 0, MEM_RELEASE):
                        ret = True
    if proc_handle is not None:
        ctypes.windll.kernel32.CloseHandle(proc_handle)
    return ret

if __name__ == "__main__":
    inject_dll(sys.argv[1], int(sys.argv[2]))