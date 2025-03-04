#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

#define BASE_BUILD_COMMAND_SIZE 256
#define MAX_COMPILER_LEN 16
#define MAX_OUTPUT_LEN 16


typedef struct {
	char *compiler;
	char *output;
	char *sourcePath;
	char **sources;
	char **includes;
	char **dependencies;
	char **compilerFlags;

	size_t includesCount;
	size_t sourcesCount;
	size_t dependenciesCount;
	size_t compilerFlagsCount;
} BuildInfo;

typedef enum {
	NOB_INFO,
	NOB_WARNING,
	NOB_ERROR
} LogLevel;



void nobLog(LogLevel level, const char *fmt, ...) {
	switch (level) {
		case NOB_INFO:
			fprintf(stderr, "[INFO] ");
			break;
		case NOB_WARNING:
			fprintf(stderr, "[WARNING] ");
			break;
    	case NOB_ERROR:
        	fprintf(stderr, "[ERROR] ");
        	break;
    	default:
        	assert("unreachable");
	}

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");

	return;
}


char *nobAppend(char *buildCommand, char **items, size_t itemsCount, size_t *capacity, const char *extra) {
	for(size_t i = 0; i < itemsCount; i++) {
		if((strlen(buildCommand)+strlen(items[i])+strlen(extra)+1) > *capacity) {
			*capacity *= 2;
			char *tmp = (char *)realloc(buildCommand, *capacity * sizeof(char));

			if(!tmp) {
				nobLog(NOB_ERROR, "Realloc failed while appending, current capacity >>> [%zd]", *capacity);
				free(buildCommand);
				return NULL;
			}

			buildCommand = tmp;
		}

		strcat(buildCommand, extra);
		strcat(buildCommand, items[i]);
		strcat(buildCommand, " ");
	}

	return buildCommand;
}


bool nobPrepare(char *command) {
	nobLog(NOB_INFO, "executed command >>> [%s]", command);
	system(command); // safer alternative
	
	return true;
}

bool nobBuild(BuildInfo *buildInfo) {
	size_t capacity = BASE_BUILD_COMMAND_SIZE;
	char *buildCommand = (char *)malloc(capacity * sizeof(char)); // check on this
	
	if(!buildCommand) {
		nobLog(NOB_ERROR, "buildCommand allocation failed!");
		return false;
	}

	if(strlen(buildInfo->compiler)+1 > MAX_COMPILER_LEN) {
		nobLog(NOB_ERROR, "Compiler string len too long");
		free(buildCommand);
		return false;
	}
	strcpy(buildCommand, buildInfo->compiler);
	strcat(buildCommand, " ");

	buildCommand = nobAppend(buildCommand, buildInfo->dependencies, buildInfo->dependenciesCount, &capacity, "-l");
	if(!buildCommand) {
		return false;
	}

	buildCommand = nobAppend(buildCommand, buildInfo->compilerFlags, buildInfo->compilerFlagsCount, &capacity, "-");
	if(!buildCommand) {
		return false;
	}

	buildCommand = nobAppend(buildCommand, buildInfo->sources, buildInfo->sourcesCount, &capacity, buildInfo->sourcePath);
	if(!buildCommand) {
		return false;
	}

	buildCommand = nobAppend(buildCommand, buildInfo->includes, buildInfo->includesCount, &capacity, "-I");
	if(!buildCommand) {
		return false;
	}
	
	int outputSize = strlen("-o ")+strlen(buildInfo->output);
	int totalSize = strlen(buildCommand)+outputSize - capacity;
	if(outputSize > MAX_OUTPUT_LEN) {
		nobLog(NOB_ERROR, "output string length too long");
		free(buildCommand);
		return false;
	} else if (totalSize > 0) {
		capacity = totalSize+1;
		char *tmp = (char *)realloc(buildCommand, capacity * sizeof(char));

		if(!tmp) {
			nobLog(NOB_ERROR, "Reallocation for output file failed current capacity >>> [%zd]", capacity);
			free(buildCommand);
			return false;
		}

		buildCommand = tmp;
	}


	strcat(buildCommand, "-o ");
	strcat(buildCommand, buildInfo->output);

	buildCommand[strlen(buildCommand)] = '\0';

	nobLog(NOB_INFO, "Build executed, build command >>> [%s]", buildCommand);
	system(buildCommand); // replace with safer alternative

	free(buildCommand);


	return true;
}
