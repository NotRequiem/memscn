.code

EXTERN Sys_GetSyscallNumber: PROC

SysNtClose PROC
	mov [rsp +8], rcx         
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 000951D2Dh       
	call Sys_GetSyscallNumber           
	add rsp, 28h
	mov rcx, [rsp+8]                     
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                   
	ret
SysNtClose ENDP

SysNtQueryVirtualMemory PROC
	mov [rsp +8], rcx         
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0C192D11Bh     
	call Sys_GetSyscallNumber             
	add rsp, 28h
	mov rcx, [rsp+8]                     
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                   
	ret
SysNtQueryVirtualMemory ENDP

SysNtOpenProcess PROC
	mov [rsp +8], rcx       
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0752F54BAh        
	call Sys_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                    
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    
	ret
SysNtOpenProcess ENDP

SysNtReadVirtualMemory PROC
	mov [rsp +8], rcx         
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00B930717h      
	call Sys_GetSyscallNumber            
	add rsp, 28h
	mov rcx, [rsp+8]                      
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                   
	ret
SysNtReadVirtualMemory ENDP

SysNtAllocateVirtualMemory PROC
	mov [rsp +8], rcx         
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0CBD3E774h        
	call Sys_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                     
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                 
	ret
SysNtAllocateVirtualMemory ENDP

SysNtFreeVirtualMemory PROC
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0831F8B8Fh        
	call Sys_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                      
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    
	ret
SysNtFreeVirtualMemory ENDP

SysNtQueryInformationProcess PROC
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0E280F928h      
	call Sys_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                      
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                 
	ret
SysNtQueryInformationProcess ENDP

end