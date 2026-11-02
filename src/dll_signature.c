#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "dll_signature.h"

typedef BOOL (WINAPI *CAT_ACQUIRE2)(HCATADMIN *, const GUID *, PCWSTR,
                                     PCCERT_STRONG_SIGN_PARA, DWORD);
typedef BOOL (WINAPI *CAT_HASH2)(HCATADMIN, HANDLE, DWORD *, BYTE *, DWORD);


static int signer_from_pkcs7_file(const WCHAR *path, DWORD content_flag,
                                  WCHAR *signer, DWORD signer_capacity)
{
    HCERTSTORE store = NULL;
    HCRYPTMSG message = NULL;
    PCMSG_SIGNER_INFO signer_info = NULL;
    PCCERT_CONTEXT certificate = NULL;
    DWORD size = 0;
    int success = 0;

    if (!path || !signer || signer_capacity == 0)
        return 0;
    signer[0] = L'\0';

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path, content_flag,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          NULL, NULL, NULL, &store, &message, NULL))
        goto cleanup;

    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0,
                          NULL, &size) || size == 0 || size > 1024 * 1024)
        goto cleanup;

    signer_info = malloc(size);
    if (!signer_info)
        goto cleanup;
    if (!CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0,
                          signer_info, &size))
        goto cleanup;

    CERT_INFO cert_info = {0};
    cert_info.Issuer = signer_info->Issuer;
    cert_info.SerialNumber = signer_info->SerialNumber;
    certificate = CertFindCertificateInStore(
        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, CERT_FIND_SUBJECT_CERT, &cert_info, NULL);
    if (!certificate)
        goto cleanup;

    success = CertGetNameStringW(certificate,
                                  CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                  0, NULL, signer, signer_capacity) > 1;

cleanup:
    if (certificate)
        CertFreeCertificateContext(certificate);
    free(signer_info);
    if (message)
        CryptMsgClose(message);
    if (store)
        CertCloseStore(store, 0);
    return success;
}

static int verify_catalog_for_algorithm(const WCHAR *path,
                                         const WCHAR *algorithm,
                                         DLL_SIGNATURE_INFO *result)
{
    int outcome = -1;
    HMODULE wintrust_module = NULL;
    HCATADMIN admin = NULL;
    HCATINFO catalog = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE *hash = NULL;

    wintrust_module = LoadLibraryW(L"wintrust.dll");
    if (!wintrust_module)
        goto cleanup;

    FARPROC acquire_proc = GetProcAddress(wintrust_module,
                                            "CryptCATAdminAcquireContext2");
    FARPROC hash_proc = GetProcAddress(wintrust_module,
                                       "CryptCATAdminCalcHashFromFileHandle2");
    CAT_ACQUIRE2 acquire2 = NULL;
    CAT_HASH2 hash2 = NULL;
    if (!acquire_proc || !hash_proc)
        goto cleanup;
    memcpy(&acquire2, &acquire_proc, sizeof(acquire2));
    memcpy(&hash2, &hash_proc, sizeof(hash2));

    if (!acquire2(&admin, NULL, algorithm, NULL, 0))
        goto cleanup;

    file = CreateFileW(path, GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto cleanup;

    DWORD hash_size = 0;
    if (!hash2(admin, file, &hash_size, NULL, 0) ||
        hash_size == 0 || hash_size > 128)
        goto cleanup;

    hash = malloc(hash_size);
    if (!hash)
        goto cleanup;
    if (!hash2(admin, file, &hash_size, hash, 0) || hash_size == 0)
        goto cleanup;

    WCHAR tag[257];
    static const WCHAR hex[] = L"0123456789ABCDEF";
    for (DWORD i = 0; i < hash_size; i++) {
        tag[2 * i] = hex[hash[i] >> 4];
        tag[2 * i + 1] = hex[hash[i] & 0x0F];
    }
    tag[2 * hash_size] = L'\0';

    outcome = 1;
    while ((catalog = CryptCATAdminEnumCatalogFromHash(
                admin, hash, hash_size, 0, &catalog)) != NULL) {
        CATALOG_INFO info = {0};
        info.cbStruct = sizeof(info);
        if (!CryptCATCatalogInfoFromContext(catalog, &info, 0)) {
            outcome = -1;
            break;
        }

        WINTRUST_CATALOG_INFO catalog_info = {0};
        catalog_info.cbStruct = sizeof(catalog_info);
        catalog_info.pcwszCatalogFilePath = info.wszCatalogFile;
        catalog_info.pcwszMemberTag = tag;
        catalog_info.pcwszMemberFilePath = path;
        catalog_info.hMemberFile = file;
        catalog_info.pbCalculatedFileHash = hash;
        catalog_info.cbCalculatedFileHash = hash_size;
        catalog_info.hCatAdmin = admin;

        WINTRUST_DATA trust = {0};
        trust.cbStruct = sizeof(trust);
        trust.dwUIChoice = WTD_UI_NONE;
        trust.fdwRevocationChecks = WTD_REVOKE_NONE;
        trust.dwUnionChoice = WTD_CHOICE_CATALOG;
        trust.pCatalog = &catalog_info;
        trust.dwStateAction = WTD_STATEACTION_VERIFY;
        trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG status = WinVerifyTrust(INVALID_HANDLE_VALUE, &action, &trust);
        trust.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(INVALID_HANDLE_VALUE, &action, &trust);

        if (status == ERROR_SUCCESS) {
            outcome = 0;
            /* The catalog is trusted; obtain its PKCS#7 signer subject. */
            signer_from_pkcs7_file(info.wszCatalogFile,
                                  CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                                  result->signer,
                                  (DWORD)(sizeof(result->signer) /
                                          sizeof(result->signer[0])));
            break;
        }
        outcome = -1; 
    }

cleanup:

    if (catalog && admin)
        CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
    free(hash);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (admin)
        CryptCATAdminReleaseContext(admin, 0);
    if (wintrust_module)
        FreeLibrary(wintrust_module);
    return outcome;
}

static int verify_catalog_signature(const WCHAR *path,
                                    DLL_SIGNATURE_INFO *result)
{
    int outcome = verify_catalog_for_algorithm(path, L"SHA256", result);
    if (outcome != 1)
        return outcome;
    return verify_catalog_for_algorithm(path, L"SHA1", result);
}

int dll_signature_inspect(const WCHAR *dll_path, DLL_SIGNATURE_INFO *result)
{
    if (!result)
        return 0;
    memset(result, 0, sizeof(*result));
    result->status = DLL_SIGNATURE_FAILED;
    result->type = DLL_SIGNATURE_TYPE_UNKNOWN;
    result->error_code = ERROR_INVALID_PARAMETER;
    if (!dll_path || !dll_path[0])
        return 0;

    WINTRUST_FILE_INFO file_info = {0};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = dll_path;

    WINTRUST_DATA trust = {0};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file_info;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(INVALID_HANDLE_VALUE, &action, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(INVALID_HANDLE_VALUE, &action, &trust);

    if (status == ERROR_SUCCESS) {
        result->status = DLL_SIGNATURE_VALID;
        result->type = DLL_SIGNATURE_TYPE_EMBEDDED;
        result->error_code = ERROR_SUCCESS;
        signer_from_pkcs7_file(dll_path,
                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                              result->signer,
                              (DWORD)(sizeof(result->signer) /
                                      sizeof(result->signer[0])));
        return 1;
    }

    if (status != TRUST_E_NOSIGNATURE) {
        result->error_code = status;
        return 1;
    }

    int catalog_result = verify_catalog_signature(dll_path, result);
    if (catalog_result == 0) {
        result->status = DLL_SIGNATURE_VALID;
        result->type = DLL_SIGNATURE_TYPE_CATALOG;
        result->error_code = ERROR_SUCCESS;
    } else if (catalog_result == 1) {
        result->status = DLL_SIGNATURE_UNSIGNED;
        result->type = DLL_SIGNATURE_TYPE_NONE;
        result->error_code = TRUST_E_NOSIGNATURE;
    } else {
        result->status = DLL_SIGNATURE_FAILED;
        result->type = DLL_SIGNATURE_TYPE_UNKNOWN;
        result->error_code = ERROR_INVALID_DATA;
    }
    return 1;
}

DLL_SIGNATURE_STATUS dll_signature_verify(const WCHAR *dll_path,
                                           LONG *error_code)
{
    DLL_SIGNATURE_INFO result;
    dll_signature_inspect(dll_path, &result);
    if (error_code)
        *error_code = result.error_code;
    return result.status;
}

int dll_signature_get_signer(const WCHAR *dll_path,
                             WCHAR *signer, DWORD signer_capacity)
{
    if (!signer || !signer_capacity)
        return 0;
    signer[0] = L'\0';
    DLL_SIGNATURE_INFO result;
    if (!dll_signature_inspect(dll_path, &result) ||
        result.status != DLL_SIGNATURE_VALID || !result.signer[0])
        return 0;
    size_t length = wcslen(result.signer) + 1;
    if (length > signer_capacity)
        return 0;
    wmemcpy(signer, result.signer, length);
    return 1;
}
