#ifndef COMMON_H
#define COMMON_H

#define BITS_IN_BYTE 8
#define KEY_MAX_LEN 32
#define LOGIN_MAX_LEN 16
#define PASSWORD_MAX_LEN 16 // Блок для шифрования всегда 16 байт

typedef struct
{
    unsigned char login[LOGIN_MAX_LEN];
    unsigned char password[PASSWORD_MAX_LEN];
} CUser;

unsigned char key[KEY_MAX_LEN];

#endif // COMMON_H
