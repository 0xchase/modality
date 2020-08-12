#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vuln() {
	char data[20];
	char temp[20] = "Please don't crash\0";

	scanf("%s", data);

	printf("The data you entered is: %s\n", data);
}

void nothing() {
	system("date");
}

int main() {
	printf("Enter the data: ");

	vuln();

	nothing();

	return 0;
}

void yeet() {
	printf("YOU WIN THIS CHALLENGE");
}
