#include <stdio.h>
#include <stdlib.h>
#include "elf64.h"

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

int check_exec(FILE* file, char* exec_name, Elf64_Ehdr* header)
{
	if(fread(header, sizeof(Elf64_Ehdr), 1, file) != 1 || header->e_type != 2)
		NOT_EXEC(name);

	return 0;
}		

int check_func(FILE* file, char* func_name, Elf64_Ehdr* header, Elf64_Shdr* section_header, Elf64_Sym* symbol_entry)
{
	if(fseek(file, header->e_shoff, SEEK_SET) != 0) return -1; // go to section header offset
	for(int i = 0; i < header->e_shnum; i++) // iterate over section header entries
	{
		if(fread(section_header, sizeof(Elf64_Shdr), 1, file) != 1) return -1; // read section header entry
		if(section_header->sh_name == ".symtab") // need to check how to translate ".symtab" to Elf64_Word
		{
			if(fseek(file, section_header->sh_offset, SEEK_SET) != 0) return -1; // go to symbol table offset
			for(int j = 0; j < (section_header->sh_size / section_header->sh_entsize); j++) // iterate over symbol table entries
			{
				if(fread(symbol_entry, sizeof(Elf64_Sym), 1, file) != 1) return -1; // read symbol table entry
				if(symbol_entry->st_name == func_name) // need to check how to translate func name from Elf64_Word to char*
					return 0;
			}
		}
	}

	printf("PRF:: <function name> not found!\n");
	return -1; // didn't find the function
	

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

	Elf64_Ehdr* header;
	Elf64_Shdr* section_header;
	Elf64_Sym* symbol_entry;

	if(check_exec(file, exec_name, header) != 0) 
	{	
		CLOSE_AND_RETURN_ERROR(file);
	}
	printf("\nFile is Exec!\n");

	if(check_func(file, func_name, header, section_header, symbol_entry) != 0)
	{
		CLOSE_AND_RETURN_ERROR(file);
	}

	if(ELF64_ST_BIND(symbol_entry->st_info) != "GLOBAL") // again, needs to translate string to ...
	{
		printf("PRF:: <function name> is not a global symbol! :(\n");
		CLOSE_AND_RETURN_ERROR(file);
	}
	printf("\nFunction exist and it GLOBAL!\n");

	if(symbol_entry->st_shndx == "UND") // function not in file, will get in runtime only (again, translate problem...)
	{

	}
	else								// function in file, needs to check which section and search for it
	{

	}

	fclose(file);
	return 0;
}

