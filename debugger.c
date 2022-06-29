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
#include <string.h>
#include "elf64.h"

#define GLOBAL_CONSTANT 1 // according to oracle website
#define MAX_SIZE 200
#define TYPE_EXEC 2

#define CLOSE_AND_RETURN_ERROR(file)						\
{															\
	fclose(file);											\
	exit(1);												\
}

#define FREE_AND_RETURN_ERROR(strtab)						\
{															\
	free(strtab);											\
	return -1;												\
}

int check_exec(FILE* file, char* exec_name, Elf64_Ehdr* header)
{
	if(fread(header, sizeof(Elf64_Ehdr), 1, file) != 1 || header->e_type != TYPE_EXEC)
		return -1;

	return 0;
}		

int get_section_header(FILE* file, char* section_name, Elf64_Ehdr* header, Elf64_Shdr* section_header)
{
	if(fseek(file, header->e_shoff + header->e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) != 0) return -1;	//go to string table's section header
	if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) return -1;	//read section header
	if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) return -1; // go to string table offset
	
	char* shstrtab = (char*)malloc(sizeof(char) * sizeof(section_header->sh_size));	//get memory to store strtab
	if(shstrtab == NULL) exit(1); // check that string table is allocated
	
	if(fread(shstrtab, section_header->sh_size, 1, file) != 1) FREE_AND_RETURN_ERROR(shstrtab);	//read string table to strtab
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ERROR(shstrtab); // go to section header offset

	for(int i = 0; i < header->e_shnum; i++)
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) FREE_AND_RETURN_ERROR(shstrtab); // read section header entry
		
		if(strcmp(shstrtab + section_header->sh_name, section_name) == 0) // compare the name of the header with ".symtab"
		{
			free(shstrtab);
			return 0;
		}
	}
	section_header = NULL;
	return -1;
}

int get_symbol_entry(FILE* file, char* str_table, char* func_name, Elf64_Ehdr* header, Elf64_Shdr* section_header, Elf64_Sym* symbol_entry, int* index)
{
	bool exist = false;
	Elf64_Shdr strtab_header;
	if(get_section_header(file, str_table, header, &strtab_header) != 0) exit(1);

	char* strtab = (char*)malloc(sizeof(char) * strtab_header.sh_size);
	if(strtab == NULL) exit(1);
	if(fseek(file, strtab_header.sh_offset, SEEK_SET) != 0) FREE_AND_RETURN_ERROR(strtab);
	if(fread(strtab, strtab_header.sh_size, 1, file) != 1) FREE_AND_RETURN_ERROR(strtab);

	Elf64_Xword num_of_entries = section_header->sh_size / section_header->sh_entsize;

	if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) FREE_AND_RETURN_ERROR(strtab); // go to symbol table offset

	for(int i = 0; i < num_of_entries; i++) // iterate over symbol table entries ------------- check the for condition ------------
	{
		if(fread(symbol_entry, section_header->sh_entsize, 1, file) != 1) FREE_AND_RETURN_ERROR(strtab); // read symbol table entry
		
		if(strcmp(strtab + symbol_entry->st_name, func_name) == 0) // compare the name of the header with the given function name
		{
			if(ELF64_ST_BIND(symbol_entry->st_info) != GLOBAL_CONSTANT) 
			{
				exist = true;
				continue;
			}
			if(index) *index = i;
			free(strtab);
			return 0;
		}
	}
	symbol_entry = NULL;
	free(strtab);
	if(exist) return 1;
	return -1; // didn't find the function
}

int check_func(FILE* file, char* str_table, char* table_name, char* func_name, Elf64_Ehdr* header, Elf64_Shdr* section_header, Elf64_Sym* symbol_entry, int* index)
{
	if(get_section_header(file, table_name, header, section_header) != 0) return -1;
	return get_symbol_entry(file, str_table, func_name, header, section_header, symbol_entry, index);
}

Elf64_Addr check_UND(FILE* file, char* func_name, Elf64_Ehdr* header, Elf64_Shdr* section_header, Elf64_Sym* symbol_entry)
{
	int index = -1;
	int func_exist = check_func(file, ".dynstr", ".dynsym", func_name, header, section_header, symbol_entry, &index);
	if(func_exist != 0)
	{
		if(func_exist == 1) // func exist but not global
		{
			printf("PRF:: %s is not a global symbol! :(\n", func_name);
		}
		else				// func doesn't exist
		{
			printf("PRF:: %s not found!\n", func_name);
		}
		return -1;
	}
	if(get_section_header(file, ".rela.plt", header, section_header) != 0) return -1;

	Elf64_Rela realloc_header;
	if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) 
		return -1; // go to function in PLT

	Elf64_Xword num_of_entries = section_header->sh_size / section_header->sh_entsize;
	for(int i = 0; i < num_of_entries; i++)
	{
		if(fread(&realloc_header, sizeof(Elf64_Rela), 1, file) != 1) return -1; // read section header entry
		if(ELF64_R_SYM(realloc_header.r_info) == index) return realloc_header.r_offset;
	}
	
	return -1;
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
	unsigned long backup_addr, original_data, data_trap, end_of_func_addr, return_data, return_trap;
	backup_addr = addr;
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

		// we removed the breakpoint from the start of the function and add breakpoint
		// at the return from the function, so if the function is recursive, we will print
		// only 1 time, only when the function returned from the original call, 
		// like the definition of the assignment

		// continue untill end of function breakpoint
		ptrace(PTRACE_CONT, child_pid, NULL, NULL);
		waitpid(child_pid, &wait_status, 0);

		// get the registers for the return value (%rax)
		ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
		
		call_counter++;
		printf("PRF:: run #%ld returned with %d\n", call_counter, (int)regs.rax); // print the returned value

		// restore the original instruction at the end of function
		regs.rip--;
		ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
		ptrace(PTRACE_POKETEXT, child_pid, (void *)end_of_func_addr, (void *)return_data);

		if(!func_in_file)
		{
			addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)backup_addr, NULL);
			original_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
 			data_trap = (original_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
		}

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
	int func_exist;

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
	char* func_name = argv[1];
	char* exec_name = argv[2];
	//char* func_name = "foo";
	//char* exec_name = "../basic_test.out";

	file = fopen(exec_name, "rb");
	if (file == NULL) exit(1);

	if(check_exec(file, exec_name, &header) != 0) 
	{	
		printf("PRF:: %s not an executable! :(\n", exec_name);
		CLOSE_AND_RETURN_ERROR(file);
	}

	func_exist = check_func(file, ".strtab", ".symtab", func_name, &header, &section_header, &symbol_entry, NULL);
	if(func_exist != 0)
	{
		if(func_exist == 1) // func exist but not global
		{
			printf("PRF:: %s is not a global symbol! :(\n", func_name);
		}
		else				// func doesn't exist
		{
			printf("PRF:: %s not found!\n", func_name);
		}
		CLOSE_AND_RETURN_ERROR(file);
	}

	if(symbol_entry.st_shndx == SHN_UNDEF) 
	{
		function_addr = check_UND(file, func_name, &header, &section_header, &symbol_entry);
		if(function_addr == (Elf64_Addr)(-1))
		{
			fclose(file);
			return 0;
		}
	}
	else								// function in file, needs to check which section and search for it
	{
		function_in_file = true;
		function_addr = symbol_entry.st_value; 
		// in executable the st_value is the memory address that he will load in
	}

	// fork process for execv file and give control for the debugging
	pid_t child_pid = run_target(exec_name, argv + 2);
	
	// run the program with the debugger
	run_breakpoint_debugger(child_pid, function_addr, function_in_file);

	fclose(file);
	return 0;
}

