#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "common.h"

//int isLat(char c)
//{
//    return (c >= (char)'0' && c <= (char)'9' ||
//            c >= (char)'a' && c <= (char)'z' ||
//            c >= (char)'A' && c <= (char)'Z');
//}

int isAllowChar(char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z'));
}

int putLogin(char* login)
{
    char* input;

    printf("Введите login:\n");
    scanf("%ms", &input);


    int len  = strlen(input);
    if(len > LOGIN_MAX_LEN)
    {
        return -1;
    }
    else
        strncpy(login, input, LOGIN_MAX_LEN);

    for(int i =0; i < len; i++)
    {
        if(!isAllowChar(input[i]))
            return -2;
    }

    if(strcmp((char*)login, "test") == 0)
        return 1;

    return 0;
}

int putPassword(char* password)
{
    char* input;

    printf("Введите password:\n");
    scanf("%ms", &input);

    int len  = strlen(input);
    if(len > PASSWORD_MAX_LEN)
    {
        return -1;
    }
    else
        strncpy(password, input, PASSWORD_MAX_LEN);

    for(int i =0; i < len; i++)
    {
        if(!isAllowChar(input[i]))
            return -2;
    }

    return 0;
}

