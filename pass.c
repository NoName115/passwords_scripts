#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void ReadPasswordsFromFile(char *filename);

void CapitalizeRandomLetter(char *password);
void ChangeRandomLetterToRandomLetter(char *password);

int StringLength(char *string)
{
  int i;
  for (i = 0; string[i] != '\0'; ++i);
  return i;
}

int main(int argc, char *argv[])
{
  srand(time(NULL));

  if (argc == 2)
  {
    if (strcmp(argv[1], ".") != 0)
    {
      ReadPasswordsFromFile(argv[1]);
      return 0;
    }
  } else
  {  
    printf("ERROR: Wrong number of arguments \n");
    exit(1);
  }

  char password[50];
  
  printf("Input password \n");
  scanf("%s", &password);

  //printf("%s \n", password);

  ChangeRandomLetterToRandomLetter(password);
  CapitalizeRandomLetter(password);

  printf("%s \n", password);
}

void ReadPasswordsFromFile(char *filename)
{
  FILE *subor = fopen(filename, "r");
  if (subor == NULL)
  {
    printf("ERROR: Opening file \n");
    exit(1);
  }

  char password[50];
  
  while (fscanf(subor, "%s", &password) == 1)
  {
    ChangeRandomLetterToRandomLetter(password);
    CapitalizeRandomLetter(password);

    printf("%s \n", password);
  }
}

void CapitalizeRandomLetter(char *password)
{
  int letterIndex = rand() % StringLength(password);
  
  if (password[letterIndex] > 96)
    password[letterIndex] = password[letterIndex] - 32;
}

void ChangeRandomLetterToRandomLetter(char *password)
{
  int letterIndex = rand() % StringLength(password);
  char firstLetter = password[letterIndex];

  while (password[letterIndex] == firstLetter)
  {
    int newLetter = (rand() % 25) + 97;
    password[letterIndex] = newLetter;
  }
}
