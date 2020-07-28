#include <stdio.h>
#include <stdlib.h>

void vuln() {
	char data[20];

	scanf("%s", data);

	printf("The data you entered is: %s\n", data);
}

int main() {
	printf("Enter the data: ");

	vuln();

	return 0;
}

void yeet() {
	printf("YOU WIN THIS CHALLENGE");
}
