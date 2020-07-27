#include <stdio.h>
#include <stdlib.h>

void vuln() {
	int temp1 = 5324;
	char data[20];
	int temp2 = 4564;

	scanf("%s", data);

	if (data[4] != 0x11 || temp1 != 5324 || temp2 != 4564) {
		exit(0);
	}

	printf("The data you entered is: %s\n", data);

	if (1 == 2) {
		printf(data);
		printf("\n");
	}
}

int main() {
	printf("Enter the data: ");

	vuln();

	return 0;
}
