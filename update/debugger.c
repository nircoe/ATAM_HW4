#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include "elf64.h"

#define GLOBAL_CONSTANT 1 // according to oracle website

#define NOT_EXEC(name)										\
{															\
	printf("PRF:: %s not an executable! :(\n", exec_name);	\
	return 1;												\
}		

#define CLOSE_AND_RETURN_ERROR(file)						\
{															\
	fclose(file);											\
	return 1;												\
}

#define FREE_AND_RETURN_ERROR(strtab)						\
{															\
	free(strtab);											\
	return -1;												\
}

#define FREE_AND_RETURN_ZERO_ERROR(strtab)					\
{															\
	free(strtab);											\
	return 0;												\
}

int check_exec(FILE* file, char* exec_name, Elf64_Ehdr* header)
{
	if(fread(header, sizeof(Elf64_Ehdr), 1, file) != 1 || header->e_type != 2)
		NOT_EXEC(name);

	return 0;
}		

int check_func(FILE* file, char* func_name, Elf64_Ehdr* header, Elf64_Shdr* section_header, Elf64_Sym* symbol_entry)
{
	/*if(fseek(file, header->e_shoff, SEEK_SET) != 0) return -1; // go to section header offset
	int i = 0;
	for(; i < header->e_shnum; i++) // iterate over section header entries
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) return -1; // read section header entry
		if(section_header->sh_name == header->e_shstrndx) // go to strtab
		{
			if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) return -1; // go to string table offset
			if(fread(strtab, section_header->sh_size, 1, file) != 1) return -1;
			break;
		}
	}
	if(i == header->e_shnum)//if you have iterated over the entire section headers, then you haven't found the strtab
		return -1;*/
		
    if(fseek(file, header->e_shoff + header->e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) != 0) return -1;	//go to string table's section header
	if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) return -1;	//read section header
	if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) return -1; // go to string table offset
	char* strtab = (char*)malloc(sizeof(char) * sizeof(section_header->sh_size));	//get memory to store strtab
	if(strtab == NULL) return -1; // check that string table is allocated
	if(fread(strtab, section_header->sh_size, 1, file) != 1) FREE_AND_RETURN_ERROR(strtab);	//read string table to strtab
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ERROR(strtab); // go to section header offset
	
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ERROR(strtab); // go to section header offset
	for(int i = 0; i < header->e_shnum; i++) // iterate over section header entries
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) FREE_AND_RETURN_ERROR(strtab); // read section header entry
		if(strcmp(strtab + section_header->sh_name, ".symtab") == 0) // compare the name of the header with ".symtab"
		{
			if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) FREE_AND_RETURN_ERROR(strtab); // go to symbol table offset
			for(int j = 0; j < (section_header->sh_size / section_header->sh_entsize); j++) // iterate over symbol table entries ------------- check the for condition ------------
			{
				if(fread(symbol_entry, sizeof(Elf64_Sym), 1, file) != 1) FREE_AND_RETURN_ERROR(strtab); // read symbol table entry
				if(strcmp(strtab + symbol_entry->st_name, func_name) == 0) // compare the name of the header with the given function name
				{
					free(strtab);
					return 0;
				}
			}
		}
	}

	printf("PRF:: <function name> not found!\n");
	free(strtab);
	return -1; // didn't find the function
}

Elf64_Addr check_UND(FILE* file, char* func_name, Elf64_Ehdr* header, Elf64_Shdr* section_header, Elf64_Sym* symbol_entry)
{
	if(fseek(file, header->e_shoff + header->e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) != 0) return 0;	//go to string table's section header
	if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) return 0;	//read section header
	if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) return 0; // go to string table offset
	char* strtab = (char*)malloc(sizeof(char) * sizeof(section_header->sh_size));	//get memory to store strtab
	if(strtab == NULL) return -1; // check that string table is allocated
	if(fread(strtab, section_header->sh_size, 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR(strtab);	//read string table to strtab
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR(strtab); // go to section header offset
	
	/*if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR(strtab); // go to section header offset
	for(int i = 0; i < header->e_shnum; i++) // iterate over section header entries
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR(strtab); // read section header entry
		if(strcmp(strtab + section_header->sh_name, ".dynsym") == 0) // compare the name of the header with ".dynsym"
		{
			if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR(strtab); // go to dynamic string table
			for(int j = 0; j < (section_header->sh_size / section_header->sh_entsize); j++) // iterate over dynamic symbol table entries ------------- check the for condition ------------
			{
				if(fread(symbol_entry, sizeof(Elf64_Sym), 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR(strtab); // read symbol table entry
				if(strcmp(strtab + symbol_entry->st_name, func_name) == 0) // compare the name of the header with the given function name
					return 0;
			}
		}
	}*/
	
	Elf64_Rela realloc_header;
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR(strtab); // go to section header offset
	for(int i = 0; i < header->e_shnum; i++) // iterate over section header entries
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR(strtab); // read section header entry
		if(strcmp(strtab + section_header->sh_name, ".rela.plt") == 0) // compare the name of the header with ".rela.plt"
		{
			if(fseek(file, section_header->sh_offset + (symbol_entry->st_name * sizeof(Elf64_Rela)), SEEK_SET) != 0) 
				FREE_AND_RETURN_ZERO_ERROR(strtab); // go to function in PLT
			if(fread(&realloc_header, sizeof(Elf64_Rela), 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR(strtab); // read section header entry
			return realloc_header.r_offset;
		}
	}

	free(strtab);
	return 0; // didn't find the function
}

pid_t run_target(const char* programname, char** argv)
{
	pid_t pid;
	
	pid = fork();
	
    if (pid > 0) {
		return pid;
		
    } else if (pid == 0) {
		/* Allow tracing of this process */
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			perror("ptrace");
			exit(1);
		}
		/* Replace this process's image with the given program */
		execv(programname, argv);
		//execl(programname, programname, NULL); // itay told me execl did problems and execv was good :)
		
	} else {
		// fork error
		perror("fork");
        exit(1);
    }
}

void run_breakpoint_debugger(pid_t child_pid, Elf64_Addr addr, bool func_in_file)
{
    int wait_status;
	size_t call_counter = 0;
    struct user_regs_struct regs;
	unsigned long original_data, data_trap, end_of_func_addr, return_data, return_trap;

    /* Wait for child to stop on its first instruction */

    wait(&wait_status);

	if(!func_in_file) // get the real function address if its not in the file
	{
		addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
	}

	// save the original instruction and set the breakpoint at the start of the function
    original_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
 	data_trap = (original_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    waitpid(child_pid, &wait_status, 0);

	while(!WIFEXITED(wait_status)) // if not finished -> stops at breakpoint -> start of the function
	{
		// get the registers
		ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
		// restore the original instruction
		regs.rip--;
		ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
		ptrace(PTRACE_POKETEXT, child_pid, (void *)addr, (void *)original_data);

		// set breakpoint at the end of function and save the original intruction there
		end_of_func_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)(regs.rsp), NULL); // get end of function address
		return_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)end_of_func_addr, NULL); // get original data from end of function
		return_trap = (return_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
		ptrace(PTRACE_POKETEXT, child_pid, (void *)end_of_func_addr, (void *)return_trap); // create breakpoint at end of function

		// continue untill end of function breakpoint
		ptrace(PTRACE_CONT, child_pid, NULL, NULL);
		waitpid(child_pid, &wait_status, 0);

		// get the registers for the return value (%rax)
		ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
		
		call_counter++;
		printf("PRF:: run #%d returned with %d\n", call_counter, regs.rax); // print the returned value

		// restore the original instruction at the end of function
		regs.rip--;
		ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
		ptrace(PTRACE_POKETEXT, child_pid, (void *)end_of_func_addr, (void *)return_data);

		// set the breakpoint again at the start of the function
		ptrace(PTRACE_POKETEXT, child_pid, (void *)addr, (void *)data_trap);

		// continue the program and wait untill get back to breakpoint
		// at the start of the function or finished the program
		ptrace(PTRACE_CONT, child_pid, NULL, NULL);
		waitpid(child_pid, &wait_status, 0);
	}
}


int main(int argc, char **argv)
{
	char *func_name, *exec_name;
	bool function_in_file = false;
	FILE *file;
	Elf64_Ehdr header;
	Elf64_Shdr section_header;
	Elf64_Sym symbol_entry;
	Elf64_Addr function_addr;

	if(argc < 3)
	{
		exit(1);
	}
	func_name = argv[1];
	exec_name = argv[2];

	file = fopen(exec_name, "rb");
	if (file == NULL) exit(1);

	if(check_exec(file, exec_name, &header) != 0) 
	{	
		CLOSE_AND_RETURN_ERROR(file);
	}
	
	if(check_func(file, func_name, &header, &section_header, &symbol_entry) != 0)
	{
		CLOSE_AND_RETURN_ERROR(file);
	}

	if(ELF64_ST_BIND(symbol_entry.st_info) != GLOBAL_CONSTANT)
	{
		printf("PRF:: <function name> is not a global symbol! :(\n");
		CLOSE_AND_RETURN_ERROR(file);
	}

	if(symbol_entry.st_shndx == SHN_UNDEF) // function not in file, will get in runtime only (not sure 100% about this macro)
	{
		function_addr = check_UND(file, func_name, &header, &section_header, &symbol_entry);
		if(function_addr == 0)
		{
			fclose(file);
			return 0;
		}
	}
	else								// function in file, needs to check which section and search for it
	{
		function_in_file = true;
		function_addr = symbol_entry.st_value; // in executable the st_value is the memory address that he will load in
	}

	// fork process for execv file and give control for the debugging
	pid_t child_pid = run_target(exec_name, argv + 2);
	
	// run the program with the debugger
	run_breakpoint_debugger(child_pid, function_addr, function_in_file);

	fclose(file);
	return 0;
}

