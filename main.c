/************************************************************************************************************************************
Написать программу на языке Си, дающую возможность шифровать и расшифровать введенный пользователем логин и пароль алгоритмом AES.
Длина ключа задается пользователем. Сам ключ генерируется автоматически.
Программа должна состоять из следующих модулей:
1) Основной модуль
2) Модуль, хранящий функции для работы с паролями и уведомлениями пользователя о внесённых данных
3) Модуль, обеспечивающий работу шифрования.
4) Доп. модули на усмотрение программиста

Реализовать проверку на корректность ввода, а также на то, что после проведенного шифрования и последующей расшифровки
логин и пароль пользователя остался верным. Выложить код на публичный репозиторий github.
*************************************************************************************************************************************/
//Допустимо вводить цифры и латинские буквы
//Даем выбрать размер ключа (1-128-бит, 2-192-бит, 3-256-бит) Это (1-16-байт, 2-24-байт, 3-32-байт)
//Генерим ключь...
//Вводим данные
//Тестируем


#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include "aes.h"
#include "tree.h"
#include "common.h"
#include "lp.h"

int keyLen = 0;

struct AES_ctx_128 ctx128;
struct AES_ctx_192 ctx192;
struct AES_ctx_256 ctx256;

typedef enum
{
    L_128,
    L_192,
    L_256
} EKeyLen;

unsigned char* genKey(EKeyLen keyLenInBits)
{
    unsigned int bits = 0;
    switch(keyLenInBits)
    {
        case L_128: bits = 128;
        break;
        case L_192: bits = 192;
        break;
        case L_256: bits = 256;
        break;
        default: bits = 256;
        break;
    }

    unsigned char* p = (unsigned char*)malloc((bits/BITS_IN_BYTE));


    srand(time(NULL));
    for(uint8_t i = 0; i < bits/BITS_IN_BYTE; i++)
    {
        p[i] = rand();
    }

    return p;

}

void printErr(int err)
{
    switch(err)
    {
    case -1:
        printf("Длина введенной строки превышает допустимую\n");
        printf("Повторите ввод верно!\n");
        break;
    case -2:
        printf("Введен недопустимый символ\n");
        printf("Повторите ввод верно!\n");
        break;
    }
}

unsigned char login[LOGIN_MAX_LEN];
unsigned char password[PASSWORD_MAX_LEN];
int main()
{

/* Предлагаем выбрать длину ключа. После выбора, ключ будет сгенерирован */
/*************************************************************************/
start:
    printf("Выберите длину ключа (1, 2 или 3):\n");
    printf("1: 128 bit\n");
    printf("2: 192 bit\n");
    printf("3: 256 bit\n");

//    unsigned char login[LOGIN_MAX_LEN];
//    unsigned char password[PASSWORD_MAX_LEN];
    EKeyLen eKeyLen = L_256;
    int keyBits = 0;

    scanf("%d", &keyBits);

    uint8_t* pkey;
    switch(keyBits)
    {
    case 1: eKeyLen = L_128;
        printf("Выбрана длина 128 бит\n");
        pkey = genKey(128);
        selectNumberOfBitsA(128);
        keyLen = 128;
        memcpy(key, pkey, 128/8);
        printf("Значение ключа:\n");
        for(int i = 0; i < 128/BITS_IN_BYTE; i++)
        {
            printf("%02X.", pkey[i]);
        }
        break;
    case 2: eKeyLen = L_192;
        printf("Выбрана длина 192 бит\n");
        pkey = genKey(192);
        selectNumberOfBitsA(192);
        keyLen = 192;
        memcpy(key, pkey, 192/8);
        printf("Значение ключа:\n");
        for(int i = 0; i < 192/BITS_IN_BYTE; i++)
        {
            printf("%02X.", pkey[i]);
        }
        break;
    case 3: eKeyLen = L_256;
        printf("Выбрана длина 256 бит\n");
        pkey = genKey(256);
        selectNumberOfBitsA(256);
        keyLen = 256;
        memcpy(key, pkey, 256/8);
        printf("Значение ключа:\n");
        for(int i = 0; i < 256/BITS_IN_BYTE; i++)
        {
            printf("%02X.", pkey[i]);
        }
        break;
    default: eKeyLen = L_256;
        printf("Выбрана длина 256 бит\n");
        pkey = genKey(256);
        printf("Значение ключа:\n");
        for(int i = 0; i < 256/BITS_IN_BYTE; i++)
        {
            printf("%02X.", pkey[i]);
        }
        break;
    }

    printf("\nВ боевой программе, ключ не будет выведен на экран.\nОн отображается только в тестовом задании\n");

    printf("\n");

    printf("Для выхода введите <quite>, для продолжения <begin>\n");

    char* appState;
    scanf("%ms", &appState);
    if(strncmp(appState, "quite", sizeof(appState)) == 0)
    {
        printf("\nПринято quite\n");
        printf("\nЗавершаем приложение\n");
        return 0;
    }
    else if(strncmp(appState, "begin", sizeof(appState)) == 0)
    {
        printf("\nПродолжаем. Вводите login, затем password\n");
    }
    else
    {
        goto start;
    }

    printf("При вводе login=<test>, переходим к тестам\n");
    printf("При вводе login=<quite>, завершаем программу\n");

    while(1)
    {
        int res = putLogin(login);
        if(res == 1)
                break;
        else if(res == -1)
        {
            printErr(res);
            continue;
        }
        else if(res == -2)
        {
            printErr(res);
            continue;
        }

        if(strcmp((char*)login, "quite") == 0)
                break;
        if(strcmp((char*)login, "start") == 0)
                goto start;

        res = putPassword(password);
        if(res == -1)
        {
            printErr(res);
            continue;
        }
        else if(res == -2)
        {
            printErr(res);
            continue;
        }

        CUser* user = malloc(sizeof(CUser));
        strcpy((char*)user->login, (char*)login);
        strcpy((char*)user->password, (char*)password);

        switch(eKeyLen)
        {
        case L_128:
            AES_init_ctx_128(&ctx128, key);
            AES_ECB_encrypt_128(&ctx128, user->password);
            break;
        case L_192:
            AES_init_ctx_192(&ctx192, key);
            AES_ECB_encrypt_192(&ctx192, user->password);
            break;
        case L_256:
            AES_init_ctx_256(&ctx256, key);
            AES_ECB_encrypt_256(&ctx256, user->password);
            break;
        }

        Node *t = NULL;

        if ((t = find(*user)) != NULL)
        {
            delete(t);
        } else
        {
            insert(*user);
        }
    }

    /* Тест */
    while(1)
    {
        printf("\n/************ Ищем пользователя:\n");
        Node *t = NULL;

        int res = putLogin(login);
        if(res == 1)
                break;
        else if(res == -1)
        {
            printErr(res);
            continue;
        }
        else if(res == -2)
        {
            printErr(res);
            continue;
        }

        if(strcmp((char*)login, "quite") == 0)
                break;
        if(strcmp((char*)login, "start") == 0)
                goto start;

        putPassword(password);
        if(res == -1)
        {
            printErr(res);
            continue;
        }
        else if(res == -2)
        {
            printErr(res);
            continue;
        }

        CUser user;
        strcpy((char*)user.login, (char*)login);
        strcpy((char*)user.password, (char*)password);

            switch(eKeyLen)
            {
            case L_128:
                AES_init_ctx_128(&ctx128, key);
                AES_ECB_encrypt_128(&ctx128, user.password);
                break;
            case L_192:
                AES_init_ctx_192(&ctx192, key);
                AES_ECB_encrypt_192(&ctx192, user.password);
                break;
            case L_256:
                AES_init_ctx_256(&ctx256, key);
                AES_ECB_encrypt_256(&ctx256, user.password);
                break;
            }

            t = find(user);
            if(t != NULL)
            {
                printf("user найден\n\n");
            }
            else
            {
                printf("user не найден\n");
            }

            printf("Продолжим поиск...");
    }

    return 0;
}
