#include <stdio.h>
#include <stdlib.h>
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

#define FREE_AND_RETURN_ERROR								\
{															\
	free(strtab);											\
	return -1;												\
}

#define FREE_AND_RETURN_ZERO_ERROR							\
{															\
	free(strtab);											\
	return -1;												\
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
		
    if(fseek(file, header.e_shoff + header.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) != 0) return -1;	//go to string table's section header
	if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) return -1;	//read section header
	if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) return -1; // go to string table offset
	char* strtab = (char*)malloc(sizeof(char) * sizeof(section_header->sh_size));	//get memory to store strtab
	if(strtab == NULL) return -1; // check that string table is allocated
	if(fread(strtab, section_header->sh_size, 1, file) != 1) FREE_AND_RETURN_ERROR;	//read string table to strtab
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ERROR; // go to section header offset
	
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ERROR; // go to section header offset
	for(int i = 0; i < header->e_shnum; i++) // iterate over section header entries
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) FREE_AND_RETURN_ERROR; // read section header entry
		if(strcmp(strtab + section_header->sh_name, ".symtab") == 0) // compare the name of the header with ".symtab"
		{
			if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) FREE_AND_RETURN_ERROR; // go to symbol table offset
			for(int j = 0; j < (section_header->sh_size / section_header->sh_entsize); j++) // iterate over symbol table entries ------------- check the for condition ------------
			{
				if(fread(symbol_entry, sizeof(Elf64_Sym), 1, file) != 1) FREE_AND_RETURN_ERROR; // read symbol table entry
				if(strcmp(strtab + symbol_entry->st_name, func_name) == 0) // compare the name of the header with the given function name
					return 0;
			}
		}
	}

	printf("PRF:: <function name> not found!\n");
	free(strtab);
	return -1; // didn't find the function
}

Elf64_Addr check_UND(FILE* file, char* func_name, Elf64_Ehdr* header, Elf64_Shdr* section_header, Elf64_Sym* symbol_entry)
{
	if(fseek(file, header.e_shoff + header.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) != 0) return 0;	//go to string table's section header
	if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) return 0;	//read section header
	if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) return 0; // go to string table offset
	char* strtab = (char*)malloc(sizeof(char) * sizeof(section_header->sh_size));	//get memory to store strtab
	if(strtab == NULL) return -1; // check that string table is allocated
	if(fread(strtab, section_header->sh_size, 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR;	//read string table to strtab
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR; // go to section header offset
	
	/*if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR; // go to section header offset
	for(int i = 0; i < header->e_shnum; i++) // iterate over section header entries
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR; // read section header entry
		if(strcmp(strtab + section_header->sh_name, ".dynsym") == 0) // compare the name of the header with ".dynsym"
		{
			if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR; // go to dynamic string table
			for(int j = 0; j < (section_header->sh_size / section_header->sh_entsize); j++) // iterate over dynamic symbol table entries ------------- check the for condition ------------
			{
				if(fread(symbol_entry, sizeof(Elf64_Sym), 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR; // read symbol table entry
				if(strcmp(strtab + symbol_entry->st_name, func_name) == 0) // compare the name of the header with the given function name
					return 0;
			}
		}
	}*/
	
	Elf64_Rela realloc_header;
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR; // go to section header offset
	for(int i = 0; i < header->e_shnum; i++) // iterate over section header entries
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR; // read section header entry
		if(strcmp(strtab + section_header->sh_name, ".rela.plt") == 0) // compare the name of the header with ".rela.plt"
		{
			if(fseek(file, section_header->sh_offset + (symbol_entry->st_name * sizeof(Elf64_Rela)), SEEK_SET) != 0) FREE_AND_RETURN_ZERO_ERROR; // go to function in PLT
			if(fread(&realloc_header, sizeof(Elf64_Rela), 1, file) != 1) FREE_AND_RETURN_ZERO_ERROR; // read section header entry
			return realloc_header->r_offset;
		}
	}

	free(strtab);
	return 0; // didn't find the function
}


int main(int argc, char **argv)
{
	if(argc < 3)
	{
		exit(1);
	}
	char* func_name = argv[1];
	char* exec_name = argv[2];
	char * args[argc - 2];
	for(int i = 0; i < argc - 3; i++)
	{
		args[i] = argv[i + 3];
	}
	FILE *file;
	file = fopen(exec_name, "rb");
	if (file == NULL) exit(1);

	Elf64_Ehdr header;
	Elf64_Shdr section_header;
	Elf64_Sym symbol_entry;

	if(check_exec(file, exec_name, &header) != 0) 
	{	
		CLOSE_AND_RETURN_ERROR(file);
	}
	printf("\nFile is Exec!\n");
	
	if(check_func(file, func_name, &header, &section_header, &symbol_entry) != 0)
	{
		CLOSE_AND_RETURN_ERROR(file);
	}

	if(ELF64_ST_BIND(symbol_entry->st_info) != GLOBAL_CONSTANT)
	{
		printf("PRF:: <function name> is not a global symbol! :(\n");
		CLOSE_AND_RETURN_ERROR(file);
	}
	printf("\nFunction exist and it GLOBAL!\n");

	Elf64_Addr function_addr
	if(symbol_entry->st_shndx == SHN_UNDEF) // function not in file, will get in runtime only (not sure 100% about this macro)
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
		
	}
	
	fclose(file);
	return 0;
}

