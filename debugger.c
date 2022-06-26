#include <stdio.h>
#include <stdlib.h>
#include "elf64.h"

#define NOT_EXEC(name)										\
{															\
	printf("PRF:: %s not an executable! :(\n", exec_name);	\
	return 1;												\
}			

int check_exec(FILE* file, char* exec_name)
{
	/*int ch, ch1;
	
	for(int i = 0; i < 16; i++)
	{
		if((ch = fgetc(file)) == EOF) NOT_EXEC(exec_name);
	}
	if((ch = fgetc(file)) != EOF || (ch1 = fgetc(file)) != EOF )
	{
		if(ch != 2 || ch1 != 0)	NOT_EXEC(exec_name); 
	}
	else NOT_EXEC(exec_name);*/

	Elf64_Ehdr header;
	if(fread(&header, sizeof(Elf64_Ehdr), 1, file) != 1 || header.e_type != 2)
		NOT_EXEC(name);

	return 0;
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
	if(check_exec(file, exec_name) != 0) 
	{	
		fclose(file);
		return 1;
	}
	printf("\nFile is Exec!\n");
	fclose(file);
	return 0;
}

