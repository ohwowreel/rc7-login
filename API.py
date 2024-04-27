
from __future__ import annotations
import os,pymem,ctypes,httpx,re,pygetwindow as gw,time,threading,lupa,pyperclip,requests,pyautogui,json,shutil,glob,string,random,winsound
#import pymem,ctypes,time,re,httpx,os,pygetwindow as gw
from datetime import datetime
import tkinter.scrolledtext as scrolledtext
from tkinter import filedialog
from tkinter import messagebox
import tkinter as tk
from pystyle import Colors, Colorate
from colorama import init, Fore;init()
InjectPattern = b'\x49\x6E\x6A\x65\x63\x74..........\x06'
#InjectPattern = b'\x49\x6e\x69\x74\x69\x61\x6c\x69\x7a\x61\x74\x69\x6f\x6e\x52\x6f\x75\x74\x69\x6e\x65..........\x06'
#InjectPattern = b'\x49\x6e\x69\x74\x69\x61\x6c\x69\x7a\x61\x74\x69\x6f\x6e\x52\x6f\x75\x74\x69\x6e\x65'
def tick():
    return time.time()
kernel32 = ctypes.WinDLL("kernel32.dll")
Roblox = ""
Valid = True
Web = False
property_descriptor_offsets = {
    "name": 0x8,
    "returntype" : 0x28,
    "security" : 0x1C,
    "GetSet" : 0x80,
}
offsets = {
     "vftable": 0,
     "self": 8,
     "property_descriptor":40,
     "class_descriptor": 24,
     "name": 72,
     "children": 80,
     "character":648,
     #E8 ? ? ? ? 8B 4D D8 8B 45 1C
     "fireclick":10609456,
     "displayname":256, # OUTDATED
     "new" : "0xdc9000",
     "name_map":"3AE46C0",
     "parent": 96,
}
def CheckForProgram(nnfn):
    try:
        pymem.Pymem(nnfn+".exe")
        return True
    except:return False
def isweb():
    global Web
    if CheckForProgram("RobloxPlayerBeta") == True:
        Web = True
        return True
    return False
def CheckForRoblox():
    global Roblox,Web
    if CheckForProgram("Windows10Universal") == True:
        Roblox = "Windows10Universal"
        return True
    if CheckForProgram("RobloxPlayerBeta") == True:
        Roblox = "RobloxPlayerBeta"
        Web = True
        return True
    return False
class synapse:
    programName = ""
    memory = None
    is64Bit = True
    is64bit = True
    pid =0
    Program = None
    PID = pid
    def GetModules() -> list:
        return list(synapse.Program.list_modules())
    def getRawProcesses():
        toreturn = []
        for i in pymem.process.list_processes():
            toreturn.append(
                [
                    i.cntThreads,
                    i.cntUsage,
                    i.dwFlags,
                    i.dwSize,
                    i.pcPriClassBase,
                    i.szExeFile,
                    i.th32DefaultHeapID,
                    i.th32ModuleID,
                    i.th32ParentProcessID,
                    i.th32ProcessID,
                ]
            )
        return toreturn

    def simpleGetProcesses():
        toreturn = []
        for i in synapse.getRawProcesses():
            toreturn.append({"Name": i[5].decode(), "Threads": i[0], "ProcessId": i[9]})
        return toreturn
    def YieldForProgram(programName):
        ProcessesList = synapse.simpleGetProcesses()
        for i in ProcessesList:
            if i["Name"] == programName:
                synapse.programName = programName
                synapse.memory = pymem.Pymem(programName)
                synapse.Program = synapse.memory
                synapse.pid = synapse.memory.process_id
                synapse.PID = synapse.memory.process_id
                return True
        return False
    def bytesToPattern(val):
        newpattern = ""
        for byte in val:
            newpattern = newpattern + '\\x' + format(byte, "02X")
        
        return bytes(newpattern, encoding="utf-8")
    def stringtobytes(string):
        byte_representation = ""
        for char in string.encode('utf-8'):
            byte_representation += "\\x" + format(char, '02x')
        return bytes(byte_representation,"utf-8")
    def intToBytes(val):
        t = [ val & 0xFF ]
        for i in range(1, 8):
            t.append((val >> (8 * i)) & 0xFF)

        return t
    def ReadStringUntilEnd( Address:int) -> str:
        if type(Address) == str:
            Address = synapse.h2d(Address)
        if Address == 0:
            return ""
        CurrentAddress = Address
        StringData = []
        LoopedTimes = 0
        while LoopedTimes < 15000:
            if synapse.Program.read_bytes(CurrentAddress,1) == b'\x00':
                break
            StringData.append(synapse.Program.read_bytes(CurrentAddress,1))
            CurrentAddress += 1
            LoopedTimes += 1
        String = bytes()
        for i in StringData:
            String = String + i
        return str(String)[2:-1]
    def ReadInstaceString(Address:int) -> str:
        try:
            length = synapse.memory.read_int(synapse.DRP(Address) + 0x10)
            if (length < 16 and length > 0):
                return synapse.ReadStringUntilEnd(synapse.DRP(Address))
            else:
                return synapse.ReadStringUntilEnd(synapse.DRP(synapse.DRP(Address)))
        except:
            return ""
    def h2d(hz: str, bit: int = 16) -> int:
        if type(hz) == int:
            return hz
        return int(hz, bit)

    def d2h(dc: int, UseAuto=None) -> str:
        if type(dc) == str:
            return dc
        if UseAuto:
            if UseAuto == 32:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
        else:
            if abs(dc) > 4294967295:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
        if len(dc) > 8:
            while len(dc) < 16:
                dc = "0" + dc
        if len(dc) < 8:
            while len(dc) < 8:
                dc = "0" + dc
        return dc
    def wb(a,v,l):
        if Suspend == True:
            synapse.suspend()
        synapse.memory.write_bytes(a,v,l)
        if Suspend == True:
            synapse.resume()
    def rb(a,l):
        if Suspend == True:
            synapse.suspend()
        e = synapse.memory.read_bytes(a,l)
        if Suspend == True:
            synapse.resume()
        return e
    def aob2re(aob: str):
        if type(aob) == bytes:
            return aob
        trueB = bytearray(b"")
        aob = aob.replace(" ", "")
        PLATlist = []
        for i in range(0, len(aob), 2):
            PLATlist.append(aob[i : i + 2])
        for i in PLATlist:
            if "?" in i:
                trueB.extend(b".")
            if "?" not in i:
                trueB.extend(re.escape(bytes.fromhex(i)))
        return bytes(trueB)
    
    def aobScan(AOB_HexArray: str, xreturn_multiple=False):
        return synapse.memory.pattern_scan_all(
            synapse.aob2re(AOB_HexArray),
            return_multiple=xreturn_multiple,
        )
    
    def gethexc(hex: str):
        hex = hex.replace(" ", "")
        hxlist = []
        for i in range(0, len(hex), 2):
            hxlist.append(hex[i : i + 2])
        return len(hxlist)

    def hex2le(hex: str):
        lehex = hex.replace(" ", "")
        lelist = []
        if len(lehex) > 8:
            while len(lehex) < 16:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)
        if len(lehex) < 9:
            while len(lehex) < 8:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)

    def calcjmpop( des, cur):
        jmpopc = (synapse.h2d(des) - synapse.h2d(cur)) - 5
        jmpopc = hex(jmpopc & (2**32 - 1)).replace("0x", "")
        if len(jmpopc) % 2 != 0:
            jmpopc = "0" + str(jmpopc)
        return jmpopc
    def isProgramGameActive():
        try:
            synapse.memory.read_char(synapse.memory.base_address)
            return True
        except:
            return False

    def DRP(Address: int, is64Bit: bool = None) -> int:
        Address = Address
        if type(Address) == str:
            Address = synapse.h2d(Address)
        if is64Bit:
            return int.from_bytes(synapse.memory.read_bytes(Address, 8), "little")
        if synapse.is64bit:
            return int.from_bytes(synapse.memory.read_bytes(Address, 8), "little")
        return int.from_bytes(synapse.memory.read_bytes(Address, 4), "little")
    
    def isValidPointer(Address: int, is64Bit: bool = None) -> bool:
        try:
            if type(Address) == str:
                Address = synapse.h2d(Address)
            synapse.memory.read_bytes(synapse.memory.read_longlong(Address, is64Bit), 1)
            return True
        except:
            return False
    def getAddressFromName(Address: str) -> int:
        if type(Address) == int:
            return Address
        AddressBase = 0
        AddressOffset = 0
        for i in synapse.GetModules():
            if i.name in Address:
                AddressBase = i.lpBaseOfDll
                AddressOffset = synapse.h2d(Address.replace(i.name + "+", ""))
                AddressNamed = AddressBase + AddressOffset
                return AddressNamed
        print("Unable to find Address: " + Address)
        return Address

    def getNameFromAddress(Address: int) -> str:
        memoryInfo = pymem.memory.virtual_query(synapse.memory.process_handle, Address)
        BaseAddress = memoryInfo.BaseAddress
        NameOfDLL = ""
        AddressOffset = 0
        for i in synapse.GetModules():
            if i.lpBaseOfDll == BaseAddress:
                NameOfDLL = i.name
                AddressOffset = Address - BaseAddress
                break
        if NameOfDLL == "":
            return Address
        NameOfAddress = NameOfDLL + "+" + synapse.d2h(AddressOffset)
        return NameOfAddress
    def readPointer(
        BaseAddress: int, Offsets_L2R: list, is64Bit: bool = None
    ) -> int:
        x = synapse.memory.read_longlong(BaseAddress, is64Bit)
        y = Offsets_L2R
        z = x
        if y == None or len(y) == 0:
            return z
        count = 0
        for i in y:
            try:
                print(synapse.d2h(x + i))
                print(synapse.d2h(i))
                z = synapse.memory.read_longlong(z + i, is64Bit)
                count += 1
                print(synapse.d2h(z))
            except:
                print("Failed to read Offset at Index: " + str(count))
                return z
        return z

    def getMemoryInfo(Address: int, Handle: int = None):
        if Handle:
            return pymem.memory.virtual_query(Handle, Address)
        else:
            return pymem.memory.virtual_query(synapse.handle, Address)

    def memoryInfoToDictionary(MemoryInfo):
        return {
            "BaseAddress": MemoryInfo.BaseAddress,
            "AllocationBase": MemoryInfo.AllocationBase,
            "AllocationProtect": MemoryInfo.AllocationProtect,
            "RegionSize": MemoryInfo.RegionSize,
            "State": MemoryInfo.State,
            "Protect": MemoryInfo.Protect,
            "Type": MemoryInfo.Type,
        }

    def setProtection(
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        pymem.resources.kernel32.VirtualProtectEx(
            synapse.memory.process_handle,
            Address,
            Size,
            ProtectionType,
            ctypes.byref(OldProtect),
        )
        return OldProtect

    def changeProtection(
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        return synapse.setProtection(Address, ProtectionType, Size, OldProtect)

    def getProtection(Address: int):
        return synapse.getMemoryInfo(Address).Protect

    def knowProtection(Protection):
        if Protection == 0x10:
            return "PAGE_EXECUTE"
        if Protection == 0x20:
            return "PAGE_EXECUTE_READ"
        if Protection == 0x40:
            return "PAGE_EXECUTE_READWRITE"
        if Protection == 0x80:
            return "PAGE_EXECUTE_WRITECOPY"
        if Protection == 0x01:
            return "PAGE_NOACCESS"
        if Protection == 0x02:
            return "PAGE_READONLY"
        if Protection == 0x04:
            return "PAGE_READWRITE"
        if Protection == 0x08:
            return "PAGE_WRITECOPY"
        if Protection == 0x100:
            return "PAGE_GUARD"
        if Protection == 0x200:
            return "PAGE_NOCACHE"
        if Protection == 0x400:
            return "PAGE_WRITECOMBINE"
        if Protection in ["PAGE_EXECUTE", "execute", "e"]:
            return 0x10
        if Protection in [
            "PAGE_EXECUTE_READ",
            "execute read",
            "read execute",
            "execute_read",
            "read_execute",
            "er",
            "re",
        ]:
            return 0x20
        if Protection in [
            "PAGE_EXECUTE_READWRITE",
            "execute read write",
            "execute write read",
            "write execute read",
            "write read execute",
            "read write execute",
            "read execute write",
            "erw",
            "ewr",
            "wre",
            "wer",
            "rew",
            "rwe",
        ]:
            return 0x40
        if Protection in [
            "PAGE_EXECUTE_WRITECOPY",
            "execute copy write",
            "execute write copy",
            "write execute copy",
            "write copy execute",
            "copy write execute",
            "copy execute write",
            "ecw",
            "ewc",
            "wce",
            "wec",
            "cew",
            "cwe",
        ]:
            return 0x80
        if Protection in ["PAGE_NOACCESS", "noaccess", "na", "n"]:
            return 0x01
        if Protection in ["PAGE_READONLY", "readonly", "ro", "r"]:
            return 0x02
        if Protection in ["PAGE_READWRITE", "read write", "write read", "wr", "rw"]:
            return 0x04
        if Protection in ["PAGE_WRITECOPY", "write copy", "copy write", "wc", "cw"]:
            return 0x08
        if Protection in ["PAGE_GUARD", "pg", "guard", "g"]:
            return 0x100
        if Protection in ["PAGE_NOCACHE", "nc", "nocache"]:
            return 0x200
        if Protection in ["PAGE_WRITECOMBINE", "write combine", "combine write"]:
            return 0x400
        return Protection

    def suspend(pid: int = None):
        if pid:
            kernel32.DebugActiveProcess(pid)
        if synapse.PID:
            kernel32.DebugActiveProcess(synapse.PID)

    def resume(pid: int = None):
        if pid:
            kernel32.DebugActiveProcessStop(pid)
        if synapse.PID:
            kernel32.DebugActiveProcessStop(synapse.PID)
    def intToAOB(intt):
        bres = util.intToBytes(intt)
        aobs = ""
        for i in range(len(bres)):
            aobs += "{:02X}".format(bres[i])
        return aobs
    def readthing(self, ExpectedAddress: int, ExpectedLength: int = 1024) -> str:
        StringCount = synapse.memory.read_int(ExpectedAddress + 0x10)
        length = (StringCount > 0 and StringCount < 16384) and StringCount or ExpectedLength
        #if StringCount > 15:
        #    return self.memory.read_string(self.synapse.memory.read_longlong(ExpectedAddress), StringCount)
        return synapse.memory.read_string(ExpectedAddress, length)
    def readRobloxString(ExpectedAddress: int, ExpectedLength: int = 1024) -> str:
        StringCount = synapse.memory.read_int(ExpectedAddress + 0x10)
        length = (StringCount > 0 and StringCount < 16384) and StringCount or ExpectedLength
        return synapse.memory.read_string(ExpectedAddress, length)
    def HttpGet(url):
        return httpx.get(url).text
    def readByte(addr: int) -> int:
        return synapse.h2d(synapse.memory.read_bytes(addr, 0x1).hex())
def toOffset(e):
    return Roblox+".exe"+"+"+e
def configureSynapse(programName):
    synapse.programName = programName
    synapse.memory = pymem.Pymem(programName+".exe")
    synapse.Program = synapse.memory
    synapse.pid = synapse.memory.process_id
    synapse.PID = synapse.memory.process_id
def ConfigureAll():
    if CheckForRoblox() == False:
        return "notfound"
    global Roblox
    configureSynapse(Roblox)
    return Roblox
def aob2re(aob):
    if type(aob) == bytes:
            return aob
    trueB = bytearray(b"")
    aob = aob.replace(" ", "")
    PLATlist = []
    for i in range(0, len(aob), 2):
        PLATlist.append(aob[i : i + 2])
    for i in PLATlist:
        if "?" in i:
            trueB.extend(b".")
        if "?" not in i:
            trueB.extend(re.escape(bytes.fromhex(i)))
    return bytes(trueB)
def readQword(address):
    try:
        return synapse.memory.read_ulonglong(address)
    except:
        return False
def readString(address):
    try:
        return synapse.memory.read_string(address)
    except:
        return False
class nameMaps:
    def __init__(self):
        self.addr = synapse.getAddressFromName(toOffset(offsets["name_map"]))
        self.namelist = {}
        while synapse.memory.read_int(self.addr) != 0:
            self.namelist[synapse.ReadInstaceString(self.addr)] = synapse.memory.read_int(self.addr)
            self.addr +=4
    def get(self,text:str) -> int:
        if text in self.namelist.keys():
            return self.namelist[text]
        else:
            return 0
class ReturnValue:
    def __init__(self, address: int) -> ReturnValue:
        self.self = address
        self.offsets = {
            "vftable": 0x0,
            "value": 0x8,
        }

    @property
    def Value(self) -> str:
        try:
            ptr = synapse.memory.read_longlong(self.self + self.offsets["value"])
            fl = synapse.memory.read_longlong(ptr + 0x18)
            if fl == 0x1F:
                ptr = synapse.memory.read_longlong(ptr)
            return synapse.readRobloxString(ptr)
        except:
            return "???"
class PropertyDescriptor:
    def __init__(self, address: int) -> PropertyDescriptor:
        self.self = address
        self.offsets = {
            "vftable": 0x0,
            "name": 0x8,
            "return_value": 0x30,
            "get_set_impl": 0x48
        }

    @property
    def Name(self) -> str:
        try:
            ptr = synapse.memory.read_longlong(self.self + self.offsets["name"])
            fl = synapse.memory.read_longlong(ptr + 0x18)
            if fl == 0x1F:
                ptr = synapse.memory.read_longlong(ptr)
            return synapse.readRobloxString(ptr)
        except:
            return "???"
        
    @property
    def Value(self) -> str:
        try:
            returnValue = ReturnValue(synapse.memory.read_longlong(self.self + self.offsets["return_value"]), synapse)
            return returnValue.Value
        except:
            return "???"
class ClassDescriptor:
    def __init__(self, address: int) -> ClassDescriptor:
        self.self = address
        self.offsets = {
            "vftable": 0x0,
            "class_name": 0x8,
            "properties": 0x40
        }

    @property
    def ClassName(self) -> str:
        try:
            ptr = synapse.memory.read_longlong(self.self + self.offsets["class_name"])
            fl = synapse.memory.read_longlong(ptr + 0x18)
            if fl == 0x1F:
                ptr = synapse.memory.read_longlong(ptr)
            return synapse.readRobloxString(ptr)
        except:
            return "???"
        
    def GetProperties(self) -> list[PropertyDescriptor]:
        prop_begin = synapse.memory.read_longlong(self.self + self.offsets["properties"])
        prop_end = synapse.memory.read_longlong(self.self + self.offsets["properties"] + 0x8)
        children = []
        if prop_begin == 0 or prop_end == 0:
            return []
        while prop_begin != prop_end:
            current_prop = synapse.memory.read_longlong(prop_begin)
            if (current_prop != 0):
                prop = PropertyDescriptor(current_prop, synapse)
                
                if not prop.Name == "???":
                    children.append(prop)
            prop_begin += 0x8
        return children
def _get_descendants(instance:Instance, descendants) -> list[Instance]:
    children = instance.GetChildren()
    for child in children:
        descendants.append(child)
        _get_descendants(child, descendants)
def get_descendants(instance:Instance) -> list[Instance]:
    descendants = []
    _get_descendants(instance, descendants)
    return descendants
class Instance:
    def __init__(self, address: int) -> Instance:
        self.self = address
        self.addr = address

    @property
    def ClassDescriptor(self) -> ClassDescriptor:
        try:
            ptr = synapse.memory.read_longlong(self.self + offsets["class_descriptor"])
            classDescriptor = ClassDescriptor(ptr)

            return classDescriptor
        except:
            return None

    @property
    def ClassName(self) -> str:
        try:
            return self.ClassDescriptor.ClassName
        except:
            return "???"
    @property
    def Name(self) -> str:
        try:
            ptr = synapse.memory.read_longlong(self.self + offsets["name"])
            fl = synapse.memory.read_longlong(ptr + 0x18)
            if fl == 0x1F:
                ptr = synapse.memory.read_longlong(ptr)

            name = synapse.readRobloxString(ptr)

            if len(name.strip()) > 1:
                return name
            else:
                return self.ClassName
        except:
            return self.ClassName
    def ChangeName(self,namse):
        try:
            ptr = synapse.memory.read_longlong(self.self + offsets["name"])
            fl = synapse.memory.read_longlong(ptr + 0x18)
            if fl == 0x1F:
                ptr = synapse.memory.read_longlong(ptr)

          #  name = synapse.readRobloxString(ptr)
            synapse.writeRobloxString(ptr,namse)
        except:
            pass
    @property
    def Value(self):
        try:
            if not self.IsA("StringValue"):
                return self.FindFirstChild("Value")
            stringAddress = synapse.memory.read_longlong(self.self + 0xC0)
            raw = ""
            if stringAddress > 0:
                length = synapse.memory.read_longlong(self.self + 0xD0)
                raw = synapse.readRobloxString(stringAddress, length)
            return raw
        except Exception as e:
            print(e)
            return ""
    @property
    def Parent(self) -> Instance:
        try:
            if synapse.memory.read_longlong(self.self + offsets["parent"]) != 0:
                return Instance(synapse.memory.read_longlong(self.self + offsets["parent"]))
            
            return None
        except:
            return None
    @property
    def HasChildren(self) -> bool:
        if self.self != 0:
            child_list = synapse.memory.read_longlong(self.self + offsets["children"])
            if child_list != 0:
                child_begin = synapse.memory.read_longlong(child_list)
                end_child = synapse.memory.read_longlong(child_list + 0x8)
                
                child_offset = 0x10

                return int((end_child - child_begin) / child_offset) > 0
        
        return False
        
    def GetChildren(self) -> list[Instance]:
        children = []
        if self.self != 0:
            child_list = synapse.memory.read_longlong(self.self + offsets["children"])
            if child_list != 0:
                child_begin = synapse.memory.read_longlong(child_list)
                end_child = synapse.memory.read_longlong(child_list + 0x8)
                
                child_offset = 0x10
                
                while child_begin != end_child:
                    current_instance = synapse.memory.read_longlong(child_begin)
                    if current_instance !=0:
                        child = Instance(current_instance)

                        if not child.Name == "???" and not child.ClassName == "???":
                            children.append(child)

                        child_begin = child_begin + child_offset
        return children
    
    def GetProperties(self) -> list[PropertyDescriptor]:
        return self.ClassDescriptor.GetProperties()
    
    def FindFirstChild(self, name: str) -> Instance:
        for child in self.GetChildren():
            if child.Name == name:
                return child
            
        return None
    
    def FindFirstChildOfClass(self, className: str) -> Instance:
        for child in self.GetChildren():
            if child.ClassName == className:
                return child
            
        return None
    def GetDescendants(self) -> list[Instance]:
        return get_descendants(self)
    def GetLastAncestor(self):
        Ancestors = []

        def GetAncestor(Object):
            if Object.Parent.Name != "???":
                GetAncestor(Object.Parent)
                Ancestors.append(Object.Parent)
            
        GetAncestor(self.Parent)

        return Ancestors[-1]
  #  def GetLastAncestorWhichIsA(self,class_name):
    #    while self:
    #        if isinstance(self, class_name):
     #           return self
     #       self = self.Parent
   #     return None
    def IsA(self, className: str) -> bool:
        return self.ClassName == className
    def GetFullName(self):
        names = []
        while self and not self.IsA("ServiceProvider"):
            names.insert(0, self.Name)
            self = self.Parent
        return ".".join(names)
    def WaitForChild(self,child):
        while True:
            if self.FindFirstChild(child) != None:
                break
        return self.FindFirstChild(child)
    def setParent(self,other:Instance):
        if Suspend == True:
            synapse.suspend()
        time.sleep(0.5)
        synapse.memory.write_longlong(self.self + offsets["parent"], other.self)
        try:
            newChildren = synapse.memory.allocate(0x400)
            time.sleep(0.5)
            synapse.memory.write_longlong(newChildren + 0, newChildren + 0x40)
            time.sleep(0.5)
            ptr = synapse.memory.read_longlong(other.self + offsets["children"])
            time.sleep(0.5)
            childrenStart = synapse.memory.read_longlong(ptr)
            time.sleep(0.5)
            childrenEnd = synapse.memory.read_longlong(ptr + 8)
            time.sleep(0.5)
            b = synapse.memory.read_bytes(childrenStart, childrenStart - childrenEnd)
            time.sleep(0.5)
            synapse.memory.write_bytes(newChildren + 0x40, b, len(b))
            time.sleep(0.5)
            e = newChildren + 0x40 + (childrenEnd - childrenStart)
            time.sleep(0.5)
            synapse.memory.write_longlong(e, other.self)
            time.sleep(0.5)
            synapse.memory.write_longlong(e + 8, synapse.memory.read_longlong(other.self + 0x10))
            time.sleep(0.5)
            synapse.memory.write_longlong(newChildren + 0x8, e)
            time.sleep(0.5)
            synapse.memory.write_longlong(newChildren + 0x10, e)
        except:pass
        if Suspend == True:
            synapse.resume()
    def __getattr__(self, name: str) -> Instance:
        return self.FindFirstChild(name)
#def GetRoot() -> Instance: # patched + credits to bloxlib / elcapor
 #   guiroot_pattern = b"\\x47\\x75\\x69\\x52\\x6F\\x6F\\x74\\x00\\x47\\x75\\x69\\x49\\x74\\x65\\x6D"
 #   root = synapse.memory.pattern_scan_all(guiroot_pattern,return_multiple=False)
#    RawDataModel = synapse.DRP(root + 0x38) 
   # DataModelAddress = RawDataModel+0x148
   # DataModel = Instance(DataModelAddress)
   # return DataModel
Suspend = False
def newinstance(className : str) -> Instance:
    global nameMaps
    nameMap = nameMaps()
    global Roblox
    FunctionToCall = synapse.getAddressFromName(toOffset(offsets["new"]))
    NewMemoryRegion = synapse.Program.allocate(100)
    returnStruct = synapse.Program.allocate(4)
    NewMemAddress = NewMemoryRegion
    HexArray = ''
    MovIntoEcxOp = 'B9' + synapse.hex2le(synapse.d2h(returnStruct))
    MovIntoEdxOp = 'BA' + synapse.hex2le(synapse.d2h(nameMap.get(className)))
    PushOP = '6A 03'
    CallOp = 'E8' + synapse.hex2le(synapse.calcjmpop(synapse.d2h(FunctionToCall),synapse.d2h(NewMemAddress + 12)))
    StoreOp = 'A3' + synapse.hex2le(synapse.d2h(NewMemAddress + 0x30))
    AddOp = '83 C4 04'
    RetOp = 'C3'
    HexArray = PushOP + MovIntoEcxOp + MovIntoEdxOp + CallOp  + AddOp + RetOp
    synapse.Program.write_bytes(NewMemAddress,bytes.fromhex(HexArray),synapse.gethexc(HexArray))
    synapse.Program.start_thread(NewMemAddress)
    retInstance = Instance(synapse.DRP(returnStruct))
    synapse.Program.free(NewMemAddress)
    synapse.Program.free(returnStruct)
    return retInstance
def returnInjectScript() -> Instance: # credits to jay
  #  if Suspend == True:
   #     synapse.suspend()
    result = synapse.memory.pattern_scan_all(InjectPattern,return_multiple=False)
    if result == None:
        return 0
 #   if Suspend == True:
     #   synapse.resume()
    bres = synapse.d2h(result)
    aobs = ""
    for i in range(1, 16 + 1):
        aobs = aobs + bres[i - 1 : i]
    aobs = synapse.hex2le(aobs)
    res = None
    try:
      #  if Suspend == True:
      #      synapse.suspend()
        res = synapse.aobScan(aobs, True)
    #    if Suspend == True:
    #        synapse.resume()
    except:pass
    if res:
        for i in res:
            result = i
            if (
                synapse.memory.read_longlong(result - offsets["name"] + 8) 
                == result - offsets["name"]
                ):
                return Instance(result - offsets["name"])
    return 0
class util:
    @staticmethod
    def intToBytes(val):
        if val == None:
            print('Cannot convert nil value to byte table')
            return
        t = [ val & 0xFF ]
        for i in range(1, 8):
            t.append((val >> (8 * i)) & 0xFF)
        return t
    @staticmethod
    def aobScan(aob,ret=True):
        try:
            return synapse.memory.pattern_scan_all(aob2re(aob),return_multiple=ret)
        except:pass
        return None
def getPlayers2() -> Instance:
    # credits to jay
    players = 0
    valid = None
    if Suspend == True:
        synapse.suspend()
    results = util.aobScan("506C6179657273??????????????????07000000000000000F")
    if Suspend == True:
        synapse.resume()
    if not results:
        return 0
    for result in results:
        if not result:
            return False
        bres = util.intToBytes(result)
        aobs = ""
        for i in range(8):
            aobs += "{:02X}".format(bres[i])
        first = False
        res = None
        try:
            if Suspend == True:
                synapse.suspend()
            res = util.aobScan(aobs)
            if Suspend == True:
                synapse.resume()
        except:pass
        if res:
            valid = False
            for res_item in res:
                result = res_item
                for j in range(10):
                    ptr = readQword(result - (8 * j))
                    if ptr:
                        ptr = readQword(ptr + 8)
                        if readString(ptr) == "Players":
                            instnc = Instance((result - (8 * j)) - 0x18)
                            if instnc.Parent.Name == "Game":
                                players = instnc
                                valid = True
                                break

                if valid:
                    break
        if valid:
            break
    if players == 0:
        return 0
    return players
def getPlayers() -> Instance:
    # credits to jay
    players = 0
    valid = None
    if Suspend == True:
        synapse.suspend()
    results = util.aobScan("506C6179657273??????????????????07000000000000000F")
    time.sleep(3)
    if Suspend == True:
        synapse.resume()
    if not results:
        return 0
    for result in results:
        if not result:
            return False
        bres = util.intToBytes(result)
        aobs = ""
        for i in range(8):
            aobs += "{:02X}".format(bres[i])
        first = False
        res = None
        time.sleep(3)
        try:
            if Suspend == True:
                synapse.suspend()
            res = util.aobScan(aobs)
            if Suspend == True:
                synapse.resume()
        except:pass
        if res:
            valid = False
            for res_item in res:
                result = res_item
                for j in range(10):
                    ptr = readQword(result - (8 * j))
                    if ptr:
                        ptr = readQword(ptr + 8)
                        if readString(ptr) == "Players":
                            instnc = Instance((result - (8 * j)) - 0x18)
                            if instnc.Parent.Name == "Game":
                                players = instnc
                                valid = True
                                break

                if valid:
                    break
        if valid:
            break
    if players == 0:
        return 0
    return players
def YieldForProgram2(programName):
    try:
        w = gw.getWindowsWithTitle(programName)
        if w !=None:
            return True
    except:
        pass
    return False
def getpymem(programName):
    try:
        w = pymem.Pymem(programName)
        if w:
            return w
    except:
        pass
    return False
def getGame():
    if Suspend == True:
        synapse.suspend()
    g = synapse.memory.pattern_scan_all(b"\x47\x75\x69\x52\x6F\x6F\x74\x00\x47\x75\x69\x49\x74\x65\x6D",return_multiple=True) # credits to bloxlib for pattern
    if Suspend == True:
        synapse.resume()
    for a in g:
        e = Instance(synapse.DRP(a+0x38)+0x148)
        if not e:
            continue
        if e.Name == "Game":
            plrs = e.FindFirstChildOfClass("Players")
            if len(plrs.GetChildren()) > 0:
                return e
    return 0
def setPlaceID(game,idd):
    synapse.memory.write_longlong(game.addr+0x140,idd)
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = '1'
import pygame
pygame.init()
def playSound(soundname):
    pygame.mixer.music.load(f'bin\\{soundname}.mp3')
    pygame.mixer.music.play()
def currenttime():
    return datetime.now().strftime('%H:%M:%S')
lua = lupa.LuaRuntime(unpack_returned_tuples=True)
def checksyntax(code):
    try:
        lua.execute(code)
    except lupa.LuaSyntaxError as e:
        c = str(e).replace("error loading code: ","")
        return c
    except Exception as e:
        print(e)
        pass
notebook = None
def getcodebox():
    current_tab_index = notebook.index("current")
    current_tab = notebook.winfo_children()[current_tab_index]
    for widget in current_tab.winfo_children():
        if isinstance(widget, tk.Frame):
            for widget in widget.winfo_children():
                if isinstance(widget,scrolledtext.ScrolledText):
                    return widget
green = Fore.GREEN
red = Fore.RED
cyan = Fore.CYAN
yellow = Fore.YELLOW
cyan2 = Fore.LIGHTBLUE_EX
Suspend = False
magenta = Fore.MAGENTA
blue = Fore.BLUE
white = Fore.WHITE
l_red = Fore.LIGHTRED_EX
version = ""
ScanningText = ""
l_green = Fore.LIGHTGREEN_EX
magenta2 = Fore.LIGHTMAGENTA_EX
def redprint(*args):
    ok = ' '.join(map(str, args))
    print(red+f"[{currenttime()}] "+ok+white)
def coolprint(*args):
    text = ' '.join(map(str, args))
    print(Colorate.Horizontal(Colors.cyan_to_green, f"[{currenttime()}] {text}", True))
Attached = False
AutoRunPath = "C:\\RC7_AUTORUN"
if not os.path.exists(AutoRunPath):
    os.makedirs(AutoRunPath)
tkwindow = None
# for easier updating #
#  [=[  ]=]
cwd = os.getcwd()
if cwd == "":
    print("cwd empty")
    exit()
workspace = os.path.join(cwd,"workspace")
def dicttoluaulist(lst):
    lua_table = "{"
    for item in lst:
        if isinstance(item, str):
            lua_table += '[==============[' + item + ']==============],'
        else:
            lua_table += str(item) + ','
    lua_table = lua_table.rstrip(',')
    lua_table += "}"
    return lua_table
def HttpGet(url):
    return httpx.get(url).text
def HttpContent(url):
    return requests.get(url).content
def readfile(pah):
    path = os.path.join(workspace, pah)

    if os.path.exists(path):
        file = open(path, "r", encoding="utf8")
        result = file.read()
        return result
    else:
        return ""
def readfile2(pah):
    path = os.path.join(cwd, pah)

    if os.path.exists(path):
        file = open(path, "r", encoding="utf8")
        result = file.read()
        return result
    else:
        return ""
def writefile(pah,data):
    path = os.path.join(workspace, pah)

    file = open(path, "w", encoding="utf8")
    file.write(data)
    file.close()
def onlyfileslist(directory):
    return [entry for entry in os.listdir(directory) if os.path.isfile(os.path.join(directory, entry))]
def listfiles(pah=None):
    path = workspace
    if pah:
        path = os.path.join(workspace, pah)
    return onlyfileslist(path)
def listfilescode(pah=None):
    path = workspace
    if pah:
        path = os.path.join(workspace, pah)
    e = onlyfileslist(path)
    contents = []
    for file in e:
        with open(workspace+"/"+file,"r",encoding="utf-8") as fl:
            content = fl.read()
            contents.append(content)
            fl.close()
    return contents
def listfiles2(pah=None):
    path = autorundir
    if pah:
        path = os.path.join(autorundir, pah)
    return onlyfileslist(path)
autorundir = "C:\\RC7_AUTORUN"
def listfiles2code(pah=None):
    path = autorundir
    if pah:
        path = os.path.join(autorundir, pah)
    e = onlyfileslist(path)
    contents = []
    for file in e:
        with open(autorundir+"/"+file,"r",encoding="utf-8") as fl:
            content = fl.read()
            contents.append(content)
            fl.close()
    return contents
def makefolder(payload):
    path = os.path.join(cwd, payload["request"]["path"])

    if not os.path.exists(path):
        os.makedirs(path)

def appendfile(payload):
    path = os.path.join(cwd, payload["request"]["path"])
    data = payload["request"]["data"]

    file = open(path, "a", encoding="utf8")
    file.write(data)
    file.close()

def isfile(payload):
    path = os.path.join(cwd, payload["request"]["path"])
    return os.path.isfile(path)

def isfolder(payload):
    path = os.path.join(cwd, payload["request"]["path"])
    return os.path.isdir(path)

def delfile(payload):
    path = os.path.join(cwd, payload["request"]["path"])
    os.remove(path)

def delfolder(payload):
    path = os.path.join(cwd, payload["request"]["path"])
    shutil.rmtree(path)

def identifyexecutor():
    return {"name":"RC7","version":"2.1","isbeta":"true"}

def focus_window():
    hwnd = ctypes.windll.user32.FindWindowW(None, "Roblox")
    ctypes.windll.user32.ShowWindow(hwnd, 5)
    ctypes.windll.user32.SetForegroundWindow(hwnd)
def listfolders(path=None):
    if path is None:
        path = workspace
    folder_contents = []
    for folder in os.listdir(path):
        folder_path = os.path.join(path, folder)
        if os.path.isdir(folder_path):
            for item in os.listdir(folder_path):
                folder_contents.append(os.path.join(folder, item))
    return folder_contents
def listfolderscontent(path=None):
    if path is None:
        path = workspace
    folder_contents = []
    for folder in os.listdir(path):
        folder_path = os.path.join(path, folder)
        if os.path.isdir(folder_path):
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isfile(item_path):  # Check if it's a file
                    with open(item_path, 'r',encoding="utf-8") as file:
                        content = file.read()
                        folder_contents.append(content)
    return folder_contents
VK_TAB = 0x09
VK_ENTER = 0x0D
VK_LBUTTON = 0x01
VK_RBUTTON = 0x02
InjectAddress = 0
def keypress(keycode):
    pyautogui.press(chr(keycode))

def mouse1click():
    if is_window_active() == "true":
        pyautogui.click(button='left')

def mouse1press():
    if is_window_active() == "true":
        pyautogui.mouseDown(button='left')

def mouse1release():
    if is_window_active() == "true":
        pyautogui.mouseUp(button='left')

def mouse2click():
    if is_window_active() == "true":
        pyautogui.click(button='right')

def mouse2press():
    if is_window_active() == "true":
        pyautogui.mouseDown(button='right')

def mouse2release():
    if is_window_active() == "true":
        pyautogui.mouseUp(button='right')

def is_window_active() -> str:
    roblox_window = gw.getWindowsWithTitle('Roblox')[0]
    active_window = gw.getActiveWindow()
    if active_window == roblox_window:
        return "true"
    else:
        return "false"
def randomstring(length=10):
    length = int(length)
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))
bridge = None
executeValue = None
lastvlhttpget = "NONE"
def GetStringValueValue(okok):
    stringAddress = synapse.memory.read_longlong(okok.self + 0xC0)
    raw = "NONE"
    if stringAddress > 0:
        length = synapse.memory.read_longlong(okok.self + 0xD0)
        raw = synapse.readRobloxString(stringAddress, length)
    return raw
def WriteStringValueValue(okok,newStrings):
    newString = json.dumps({
        "request": {
            "string": newStrings
        }
    })
    truepayloade = json.loads(newString)
    newString = json.dumps(truepayloade)
    newStringPtr = synapse.memory.allocate(len(newString))
    synapse.memory.write_string(newStringPtr, newString)
    synapse.memory.write_bytes(okok.self + 0xD0, bytes.fromhex(synapse.hex2le(synapse.d2h(len(newString)))), 8)
    synapse.memory.write_longlong(okok.self + 0xC0, newStringPtr)
httpgetstringvalue = None
httpgetresultvalue = None
game = None
LogsPath = [
    os.path.expandvars(r'%LOCALAPPDATA%\Roblox\logs'),
    os.path.expandvars(r'%LOCALAPPDATA%\Packages\ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr\LocalState\logs')
]
bridgenam = "ebodegf"
bregde = None
bregde2 = None
def readvalue(bres):
    result = "NONE"
    try:
        result = GetStringValueValue(bres)
    except:pass
    return result
def findlog(ff):
    LogsFolder = LogsPath[1]
    if isweb():
        LogsFolder = LogsPath[0]
    LLFP = max(glob.glob(LogsFolder + "/*"), key=os.path.getmtime)
    file_content = open(LLFP, "r",encoding="utf8").read()
    matches = re.findall(rf'{ff}\s+(\S+)', file_content)
    if matches:
        last_match = matches[-1]
        return last_match
    return "NONE"
def replace(ok:str,match,dp):
    return ok.replace(match,dp)
writefilecalled = False
files = None
requestss = None
def writefileomg():
    global files
    files = game.ReplicatedStorage.Files
    for des in files.GetDescendants():
        if des.Name.find(" s4331"):
            rawName = des.Name.replace(" s4331","")
            print("writefile file Name is",rawName)
            value = readvalue(des)
            if value == "NONE":
                print("failed to read stringvalue value (writefile error)")
                return
            writefile(rawName,value)
httpgetname = "httpgetcall"
def httpgetomg():
    global requestss
    z = requestss.FindFirstChild(httpgetname).URL
    vz = requestss.FindFirstChild(httpgetname).Result
    zs = readvalue(z)
    print(zs)
    if zs == "NONE":
        print("failed to get value")
        return
    v = HttpGet(zs)
    WriteStringValueValue(z,vz)
lasturl = ""
lastclipboard = ""
lastmouse1clickcalled = ""
lastcancelwritefile = ""
lastcls = ""
def startChecks():
    global lasturl,lastclipboard,lastcancelwritefile,lastcls,lastmouse1clickcalled
    files = game.ReplicatedStorage.Files
    storage = game.ReplicatedStorage
    url = storage.httpurl.urlvalue
    setclipstorage = storage.setclipboardvalues
    setclipvalue = setclipstorage.val
    httpresult = storage.httpresult.resultvalue
    while True:
        HttpGetURL = findlog("httpgetcalled")
        if HttpGetURL != "NONE" and HttpGetURL != "" and HttpGetURL != lasturl:
            print("url changed",HttpGetURL)
            resulty = HttpGet(HttpGetURL)
            WriteStringValueValue(httpresult,resulty)
            print("wrote")
        lasturl = findlog("httpgetcalled")




        FileName = findlog("writefile_filenameis")
        cancelwritefile = findlog("cancelwritefile")
        if FileName != "NONE" and FileName != "" and cancelwritefile != lastcancelwritefile:
            with open(workspace+f"/{FileName}","w",encoding="utf-8"):
                time.sleep(0.2) # maybe it does not create it fast on roblox
                file = files.FindFirstChild(FileName)
                writefile(FileName,file.FileContent.Value)
        lastcancelwritefile = findlog("cancelwritefile")
        clipboardcalled = findlog("setclipbaordcalledxdihatemyselfomg")
        if clipboardcalled != "NONE" and clipboardcalled != lastclipboard and clipboardcalled != '':
            big = setclipvalue.Value
            print(big)
            pyperclip.copy(big)
        lastclipboard = findlog("setclipbaordcalledxdihatemyselfomg")

        clearconsole = findlog("clearconsoleomg")
        if clearconsole != lastcls and clearconsole != "" and clearconsole != "NONE":
            os.system("cls")
        lastcls = findlog("clearconsoleomg")

        click1called = findlog("mouse1clickcalled")
        if click1called != lastmouse1clickcalled and click1called != "NONE":
            mouse1click()
        lastmouse1clickcalled = findlog("mouse1clickcalled")
        time.sleep(0.3)
localplayergui = "game:GetService('Players').localPlayer:FindFirstChildOfClass('PlayerGui')"
def level2ify(s):
    bro = replace(s,"Game","game")
    bro = replace(bro,"game.CoreGui",localplayergui)
    bro = replace(bro,"game:GetService('CoreGui')",localplayergui)
    bro = replace(bro,'game:GetService("CoreGui")',localplayergui)
    bro = replace(bro,"game:HttpGet","httpGet")
    return bro
first = True
lastbig = ""
def startAll():
    e = threading.Thread(target=startChecks,daemon=True)
    e.start()
    return f"""local autorun = {dicttoluaulist(listfiles2code())}
for i,v in pairs(autorun) do
loadstring(v)()
end"""
def AutoRun():
    def autorun():
        global lastbig
        big = findlog("rc7loadedaaaaaaa")
        if big != lastbig and big != "NONE" and lastbig != "":
             print("hjack loaded")
             time.sleep(1)
             startAll()
        lastbig = findlog("rc7loadedaaaaaaa")
    e = threading.Thread(target=autorun,daemon=True)
    e.start()
def EXE(codee,local:Instance):
    global bridge,executeValue,httpgetstringvalue,lastvlhttpget,game,httpgetresultvalue,first
    if bridge == None:
        bridge = local.FindFirstChild("ExternalExecutorCore")
    if executeValue == None:
        executeValue = bridge.FindFirstChild("ExecuteValue")
    if game == None:
        game = local.Parent.Parent
   # synapse.suspend()
    funcs = f"""if workspace:FindFirstChild("filestarted") then
	local b = Instance.new("Folder",workspace)
	b.Name = "filestarted"
end
getgenv().updatefiles = newcclosure(function()
	_G.Files:ClearAllChildren()
	local filess = {dicttoluaulist(listfiles())}
	local filessource = {dicttoluaulist(listfilescode())}
	for i,v in pairs(filess) do
		local new = Instance.new("Folder",_G.Files)
		new.Name = v
		local nam = Instance.new("StringValue",new)
		nam.Name = "FileName"
		nam.Value = "dont use this anymore"
		local contents = Instance.new("StringValue",new)
		contents.Name = "FileContent"
		contents.Value = filessource[i]
	end

    local folders = {dicttoluaulist(listfolders())}
    local folderscontent = {dicttoluaulist(listfolderscontent())}
    for i,v in pairs(folders) do
		local new = Instance.new("Folder",_G.Files)
		new.Name = v:gsub("\\\\","/")
		local nam = Instance.new("StringValue",new)
		nam.Name = "FileName"
		nam.Value = "dont use this anymore"
		local contents = Instance.new("StringValue",new)
		contents.Name = "FileContent"
		contents.Value = folderscontent[i]
	end
end)
updatefiles()
getgenv().isrbxactive = newcclosure(function()
	return {is_window_active()}
end)
getgenv().fireclickdetector = newcclosure(function(cdd,dist)
    if not type(cdd) == Instance then
        error("Instance expected")
    end
    if not cdd.ClassName == "ClickDetector" then
    error("ClickDetector expected")
    end
    local Dist = 0.0
    if dist then
        Dist = tonumber(dist)
    end
    error("firecd not out yet")
   -- local FnFire = syn.RobloxBase(OBFUSCATED_NUM_UNCACHE(syn.Offsets.ClickDetector.FireClick))

 --   FnFire(CDetector, Dist, Plr)
end)
getgenv().cwd = [==============[{cwd}]==============]
getgenv().currentdir = getgenv().cwd
getgenv().cdir = getgenv().cwd
getgenv().currentworkingdirectory = getgenv().cwd
getgenv().currentdirectory = getgenv().cwd
spawn(function()
{codee}
end)

"""
    code = funcs
    code = level2ify(code)
   # ok = re.findall("httpGet\(",code)
    #ok.remove("httpGet(")
    #if len(ok) > 0:
   #     for aeee in ok:
   #         httpgetomg()
    if game.Workspace.filestarted == None:
        code = code + startAll()
    WriteStringValueValue(executeValue,code + f"  ransssdomssasdajhleloeoworld = [==============[{randomstring(5)}]==============]")

def Attach():
    global game,players,localplayer,Attached
   # threading.Thread(target=AutoRun,daemon=True).start()
    ok = ConfigureAll()
    if ok == "notfound":
        redprint("Roblox not found")
        Attached = False
        return False
    coolprint("Attaching, PID is :",synapse.memory.process_id)
    InjectScript = 0
    try:
        if Suspend == True:
            game = getPlayers2().Parent
        else:
            game = getPlayers().Parent
    except Exception as e:
        redprint("Failed to find Game :",str(e))
        Attached = False
        return
    if game == 0:
        redprint("Failed to find Game")
        Attached = False
        return
    coolprint(f"Got {game.Name} :",hex(game.addr))
    try:
        InjectScript = returnInjectScript()
    except Exception as e:
        redprint("Failed to find Inject LocalScript :",str(e))
        Attached = False
        return
    if InjectScript == 0:
        print("Inject LocalScript not found")
        Attached = False
        return
    coolprint("Almost done")
    players = game.FindFirstChildOfClass("Players")
    localplayer = players.GetChildren()[0]
    character = Instance(synapse.memory.read_longlong(localplayer.addr+offsets["character"]))
    #displayname = synapse.readRobloxString(localplayer.addr+offsets["displayname"])
    localscript = None
    for v in character.GetChildren():
        if v.Name != "ClientInputHandler" and v.IsA("LocalScript"):
            localscript = v
            break
    if localscript == None:
        redprint("Character has no LocalScript to attach in")
        Attached = False
    b = synapse.rb(InjectScript.addr + 0x100, 0x150)
    synapse.wb(localscript.addr + 0x100, b, len(b))
    localscript.setParent(localplayer.FindFirstChildOfClass("PlayerScripts"))
    coolprint("Attached :",hex(localscript.addr))
    Attached = True
    return
def ask(s,b):
    winsound.PlaySound("SystemQuestion", winsound.SND_ALIAS | winsound.SND_ASYNC)
    result = messagebox.askquestion(s,b)
    if result == "yes":
        return True
    return False
def msgbox(b):
    messagebox.showinfo("RC7", b)
def errorbox(b):
    messagebox.showerror("RC7", b)
def warnbox(b):
    messagebox.showwarning("RC7", b)
def info(b):
    messagebox.showinfo("RC7", b, icon=None)
Output = None
def setoutput(b):
    Output.config(state="normal")
    outputtext = Output.get(1.0,tk.END)
    txt = outputtext + f"{b}\n"
    Output.insert(tk.END,txt)
    Output.config(state="disabled")
class Api:
    def Attach():
        e = threading.Thread(target=Attach,daemon=True)
        e.start()
    def WordWrap():
        CodeBox = getcodebox()
        current_wrap = CodeBox.cget("wrap")
        new_wrap = ""
        if current_wrap == "none":
            new_wrap = "word"
        elif current_wrap == "word":
            new_wrap = "none"
        CodeBox.config(wrap=new_wrap)
    def IsWeb():
        CodeBox = getcodebox()
        ok = ConfigureAll()
        if ok == "notfound":
            return "notfound"
        return ok == "RobloxPlayerBeta"
    def Get():
        CodeBox = getcodebox()
        return CodeBox.get(1.0,tk.END)
    def Clear():
        CodeBox = getcodebox()
        CodeBox.delete(1.0, tk.END)
        Output.config(state="normal")
        Output.delete(1.0,tk.END)
        Output.config(state="disabled")
    def Open():
        CodeBox = getcodebox()
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("Lua files", "*.lua"),("All files", "*.*")])
        if file:
            try:
                ok = open(file, "r", encoding="utf8")
                result = ok.read()
                Api.Clear(None)
                CodeBox.insert(tk.END, result)
                ok.close()
            except Exception as e:
                print(e)
    def Save():
        savetoautorun = ask("Save script","Save to Autorun directory?")
        file = None
        if savetoautorun:
            file = filedialog.asksaveasfilename(initialdir=AutoRunPath,filetypes=[("Text files", "*.txt"), ("Lua files", "*.lua"),("All files", "*.*")])
        else:
            file = filedialog.asksaveasfilename(filetypes=[("Text files", "*.txt"), ("Lua files", "*.lua"),("All files", "*.*")])
        if file:
            try:
                with open(file,"w",encoding="utf-8") as filee:
                    filee.write(Api.Get())
            except Exception as e:
                print(e)
    def CloseRoblox():
        if ConfigureAll() == "RobloxPlayerBeta":
            os.system("""taskkill /im "RobloxPlayerBeta.exe" /F >NUL 2>&1""")
            info("Process terminated.")
        if ConfigureAll() == "Windows10Universal":
            os.system("""taskkill /im "Windows10Universal.exe" /F >NUL 2>&1""")
            info("Process terminated.")
    def Execute(code):
        syntax = checksyntax(code)
        if isinstance(syntax,str):
            setoutput(syntax)
            return
        if Attached:
            EXE(code,localplayer)
        else:
            redprint("not attached")
    def ExecuteText():
        syntax = checksyntax(Api.Get())
        if isinstance(syntax,str):
            setoutput(syntax)
            return
        if Attached:
            e = threading.Thread(target=EXE,args=(Api.Get(),localplayer),daemon=True)
            e.start()
        else:
            redprint("not attached")