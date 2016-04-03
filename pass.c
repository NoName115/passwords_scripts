#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void ReadPasswordsFromFile(char *filename);

void CapitalizeRandomLetter(char *password);
void ChangeRandomLetterToRandomLetter(char *password);

int numberOfArguments;
int *rules;

int StringLength(char *string)
{
  int i;
  for (i = 0; string[i] != '\0'; ++i);
  return i;
}

void PrintHelp()
{
  printf("Arguments: \n");
  printf("  '.' - write password from keyboardi \n");
  printf("  'FileName' - load passwords from file \n");
  
  printf("\nPassword rules: \n");
  printf("  '1' - Change random letter to random letter \n");
  printf("  '2' - Capitalize random letter \n");
}

void ReadRulesFromArgument(int argc, char *argv[])
{
  rules = malloc(sizeof(int) * (argc - 2));
  
  int wac = 0;

  for (int i = 2; i < argc; i++)
  {
    if (!strcmp(argv[i], "1"))
    {    
      rules[numberOfArguments] = 1;
    } else
    if (!strcmp(argv[i], "2"))
    {
      rules[numberOfArguments] = 2;
    } else
    {
      numberOfArguments--;
      wac++;
      printf("ERROR: Wrong argument - %s \n", argv[i]);
    }
    
    numberOfArguments++;

    //printf("CYKLUS \n");
  }

  if (wac == argc - 2)
  {
    printf("All arguments are wrong \n");
    exit(1);
  }
}

void ApplyRules(char *pass)
{
  for (int i = 0; i < numberOfArguments; i++)
  {
    switch (rules[i])
    {
      case 1:
        ChangeRandomLetterToRandomLetter(pass);
        break;
      case 2:
        CapitalizeRandomLetter(pass);
        break;
      default:
        //printf("ERROR: Applyrules error - %s \n", rules[i]);
        break;
    }
  }
}

int main(int argc, char *argv[])
{
  srand(time(NULL));

  if (argc == 2)
  {
    if (!strcmp(argv[1], "--help"))
    {
      PrintHelp();
      return 0;
    }
  } else
  if (argc >= 2)
  {
    ReadRulesFromArgument(argc, argv);
    
    if (strcmp(argv[1], ".") != 0)
    {
      ReadPasswordsFromFile(argv[1]);
      return 0;
    }
    //Input from keyboard  
    char password[50];
  
    printf("Input password \n");
    scanf("%s", &password);

    ApplyRules(password);

    printf("%s \n", password);

  } else
  {
    printf("Write --help \n");
    exit(1);
  }
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
    ApplyRules(password);
    
    //ChangeRandomLetterToRandomLetter(password);
    //CapitalizeRandomLetter(password);

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
