#ifndef DLL_SIGNATURE_H
#define DLL_SIGNATURE_H

#include <windows.h>

typedef enum {
    DLL_SIGNATURE_VALID,
    DLL_SIGNATURE_UNSIGNED,
    DLL_SIGNATURE_FAILED
} DLL_SIGNATURE_STATUS;

typedef enum {
    DLL_SIGNATURE_TYPE_UNKNOWN,
    DLL_SIGNATURE_TYPE_NONE,
    DLL_SIGNATURE_TYPE_EMBEDDED,
    DLL_SIGNATURE_TYPE_CATALOG
} DLL_SIGNATURE_TYPE;

typedef struct {
    DLL_SIGNATURE_STATUS status;
    DLL_SIGNATURE_TYPE type;
    LONG error_code;
    WCHAR signer[256];
} DLL_SIGNATURE_INFO;

int dll_signature_inspect(const WCHAR *dll_path, DLL_SIGNATURE_INFO *result);

DLL_SIGNATURE_STATUS dll_signature_verify(const WCHAR *dll_path,
                                           LONG *error_code);
int dll_signature_get_signer(const WCHAR *dll_path,
                             WCHAR *signer, DWORD signer_capacity);

#endif
