// Altbase's private console adapter for the unmodified MWC reference wallet.
// rpassword 4.x on Windows requires a console input handle. The wallet password
// arrives only on this process's stdin, then goes to a private ConPTY after the
// password prompt. No console output is exposed, logged or written to disk.
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

static void append_arg(wchar_t *out, size_t *at, const wchar_t *arg) {
  out[(*at)++]=L'"';
  size_t slashes=0;
  for (;*arg;arg++) {
    if(*arg==L'\\'){slashes++;continue;}
    if(*arg==L'"'){for(size_t j=0;j<slashes*2+1;j++)out[(*at)++]=L'\\';out[(*at)++]=L'"';}
    else{for(size_t j=0;j<slashes;j++)out[(*at)++]=L'\\';out[(*at)++]=*arg;}
    slashes=0;
  }
  for(size_t j=0;j<slashes*2;j++)out[(*at)++]=L'\\';
  out[(*at)++]=L'"';out[(*at)++]=L' ';out[*at]=0;
}
int wmain(int argc,wchar_t **argv) {
  if(argc<2)return 2;
  char password[512]={0};DWORD count=0;size_t length=0;
  while(length<sizeof(password)-2){char c;
  if(!ReadFile(GetStdHandle(STD_INPUT_HANDLE),&c,1,&count,NULL)||!count)break;
  if(c=='\n')break;
  if(c!='\r')password[length++]=c;}
  if(!length)return 3;
  password[length++]='\r';
  size_t capacity=8;for(int i=1;i<argc;i++)capacity+=2*wcslen(argv[i])+4;
  if(capacity>32760){SecureZeroMemory(password,sizeof(password));return 4;}
  wchar_t *cmd=calloc(capacity,sizeof(wchar_t));size_t at=0;
  for(int i=1;i<argc;i++)append_arg(cmd,&at,argv[i]);
  HANDLE inputRead=NULL,inputWrite=NULL,outputRead=NULL,outputWrite=NULL;
  HPCON console=NULL;HANDLE job=NULL;PROCESS_INFORMATION pi={0};STARTUPINFOEXW si={0};int code=5;
  if(!CreatePipe(&inputRead,&inputWrite,NULL,0)||!CreatePipe(&outputRead,&outputWrite,NULL,0))goto done;
  if(FAILED(CreatePseudoConsole((COORD){120,30},inputRead,outputWrite,0,&console)))goto done;
  CloseHandle(inputRead);inputRead=NULL;CloseHandle(outputWrite);outputWrite=NULL;
  SIZE_T bytes=0;InitializeProcThreadAttributeList(NULL,1,0,&bytes);
  si.lpAttributeList=HeapAlloc(GetProcessHeap(),0,bytes);si.StartupInfo.cb=sizeof(si);
  if(!InitializeProcThreadAttributeList(si.lpAttributeList,1,0,&bytes)||!UpdateProcThreadAttribute(si.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,console,sizeof(console),NULL,NULL))goto done;
  job=CreateJobObjectW(NULL,NULL);JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if(!job||!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)))goto done;
  if(!CreateProcessW(argv[1],cmd,NULL,NULL,FALSE,EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED,NULL,NULL,&si.StartupInfo,&pi))goto done;
  if(!AssignProcessToJobObject(job,pi.hProcess)){TerminateProcess(pi.hProcess,6);goto done;}
  ResumeThread(pi.hThread);
  ULONGLONG deadline=GetTickCount64()+30000;int supplied=0;char tail[128]={0};size_t tailLen=0;
  while(WaitForSingleObject(pi.hProcess,20)==WAIT_TIMEOUT){
    DWORD available=0;
    if(PeekNamedPipe(outputRead,NULL,0,NULL,&available,NULL)&&available){
      char data[4096];DWORD read=0;
      if(ReadFile(outputRead,data,available>sizeof(data)?sizeof(data):available,&read,NULL)){
        if(!supplied)for(DWORD i=0;i<read;i++){
          if(tailLen==sizeof(tail)-1){memmove(tail,tail+1,--tailLen);}
          tail[tailLen++]=data[i];tail[tailLen]=0;
          if(strstr(tail,"Password:")){
            DWORD written=0;
  if(!WriteFile(inputWrite,password,(DWORD)length,&written,NULL)||written!=length)goto done;
            SecureZeroMemory(password,sizeof(password));supplied=1;break;
          }
        }
        SecureZeroMemory(data,sizeof(data));
      }
    }
    if(!supplied&&GetTickCount64()>deadline)goto done;
  }
  {DWORD result=1;
  if(GetExitCodeProcess(pi.hProcess,&result))code=(int)result;}
done:
  SecureZeroMemory(password,sizeof(password));
  if(job)CloseHandle(job);
  if(pi.hThread)CloseHandle(pi.hThread);
  if(pi.hProcess)CloseHandle(pi.hProcess);
  if(console)ClosePseudoConsole(console);
  if(si.lpAttributeList){DeleteProcThreadAttributeList(si.lpAttributeList);HeapFree(GetProcessHeap(),0,si.lpAttributeList);}
  if(inputRead)CloseHandle(inputRead);
  if(inputWrite)CloseHandle(inputWrite);
  if(outputRead)CloseHandle(outputRead);
  if(outputWrite)CloseHandle(outputWrite);
  free(cmd);return code;
}
