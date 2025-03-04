#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "nob.h"



bool buildProduction(void) {
	return true;
}

bool buildTesting(void) {
	BuildInfo *buildInfo = malloc(sizeof(BuildInfo));
	if (!buildInfo) {
		nobLog(NOB_ERROR, "Allocation for buildInfo failed!");
		return false;
	}

	nobPrepare("bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h");

	buildInfo->compiler = "clang";
	buildInfo->output = "omega.bpf.o";
	buildInfo->sourcesCount = 1;
	buildInfo->sources = malloc(buildInfo->sourcesCount * sizeof(char *));
	buildInfo->sourcePath = "src/";
	buildInfo->sources[0] = "main.bpf.c";

	buildInfo->compilerFlagsCount = 4;
	buildInfo->compilerFlags = malloc(buildInfo->compilerFlagsCount * sizeof(char *));

	buildInfo->compilerFlags[0] = "O3";
	buildInfo->compilerFlags[1] = "g";
	buildInfo->compilerFlags[2] = "target bpf";
	buildInfo->compilerFlags[3] = "c";

	nobBuild(buildInfo);
	nobPrepare("bpftool gen skeleton omega.bpf.o name omega > omega.skel.h");

	free(buildInfo->sources);
	free(buildInfo->compilerFlags);
	free(buildInfo);

	buildInfo = malloc(sizeof(BuildInfo));
	if (!buildInfo) {
		nobLog(NOB_ERROR, "Allocation for buildInfo failed!");
		return false;
	}


	buildInfo->compiler = malloc(MAX_COMPILER_LEN * sizeof(char));
	buildInfo->output = malloc(MAX_OUTPUT_LEN * sizeof(char));
	buildInfo->compiler = "clang";
	buildInfo->output = "loader";
	buildInfo->sourcesCount = 1;
	buildInfo->sources = malloc(buildInfo->sourcesCount * sizeof(char *));
	buildInfo->sourcePath = "src/";
	buildInfo->sources[0] = "loader.c";


	buildInfo->dependenciesCount = 2;
	buildInfo->dependencies = malloc(buildInfo->dependenciesCount * sizeof(char *));
	buildInfo->compilerFlagsCount = 0;
	buildInfo->dependencies[0] = "bpf";
	buildInfo->dependencies[1] = "elf";

	nobBuild(buildInfo);

	free(buildInfo->sources);
	free(buildInfo->dependencies);
	free(buildInfo);


	return true;
}

void cleanup(void) {
	nobPrepare("rm vmlinux.h omega.bpf.o omega.skel.h loader");
}

int main(int argc, char **argv) {
	(void)argv;
	if (argc <= 1) {
		buildTesting();
	} else {
		cleanup();
	}

	return 0;
}
