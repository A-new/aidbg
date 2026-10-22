#include <windows.h>
#include <stdio.h>
#include <string.h>
typedef LONG(__stdcall* Q)(HANDLE, ULONG, PVOID, ULONG, PULONG);
int main(){
  Q q=(Q)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess");
  unsigned char buf[48]; ULONG rl=0;
  q(GetCurrentProcess(),0,buf,48,&rl);
  unsigned long long peb=0; memcpy(&peb,buf+8,8);
  unsigned char p[0x200];
  if(!ReadProcessMemory(GetCurrentProcess(),(LPCVOID)peb,p,sizeof(p),NULL)){printf("read fail\n");return 1;}
  unsigned long long ph=0; memcpy(&ph,p+0x30,8);
  printf("PEB=%llX ProcessHeap(0x30)=%llX\n",peb,ph);
  for(unsigned o=0;o<0x200;o+=8){
    unsigned long long v=0; memcpy(&v,p+o,8);
    if(v && v>0x10000 && v<0x0000800000000000ULL){
      unsigned long long first=0;
      if(ReadProcessMemory(GetCurrentProcess(),(LPCVOID)v,&first,8,NULL) && first==ph)
        printf("  <-- ProcessHeaps candidate at PEB+0x%03X (array at %llX)\n",o,v);
    }
    if(v==ph && o!=0x30) printf("  offset 0x%03X also holds ProcessHeap\n",o);
  }
  return 0;
}
