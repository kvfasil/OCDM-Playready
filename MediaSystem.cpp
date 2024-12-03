/*
 * Copyright 2016-2017 TATA ELXSI
 * Copyright 2016-2017 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>
#include <vector>
#include <iostream>
#include <string.h>

#include "MediaSession.h"
#include <cryptalgo/cryptalgo.h>
#include <interfaces/IDRM.h>
#include <plugins/plugins.h>

// <plugins/plugins.h> has its own TRACING mechanism. We do not want to use those, undefine it here to avoid a warning.
// with the TRACE macro of the PLAYREADY software.
#define PR_4_4
#undef TRACE

using namespace std;
using namespace WPEFramework;
using SafeCriticalSection = Core::SafeSyncType<Core::CriticalSection>;

// Each challenge saves a nonce to the PlayReady3 nonce store, and each license
// bind removes a nonce. The nonce store is also a FIFO, with the oldest nonce
// rolling off if the store is full when a new challenge is generated. This can
// be a problem if the client generates but does not process a number of licenses
// greater than the nonce fifo. So NONCE_STORE_SIZE is reported to the client
// via the getLdlSessionLimit() API.
const uint32_t NONCE_STORE_SIZE = 100;

// #ifdef test
extern DRM_CONST_STRING g_dstrDrmPath;
Core::CriticalSection drmAppContextMutex_;
DRM_CONST_STRING g_dstrCDMDrmStoreName;
// #endif

bool calcFileSha256 (const std::string& filePath, uint8_t hash[], uint32_t hashLength )
{
    bool result(false); 

    ASSERT(filePath.empty() == false);

    Core::DataElementFile dataBuffer(filePath, Core::File::USER_READ);

    if ( dataBuffer.IsValid() == false ) {
        fprintf(stderr,"Failed to open %s", filePath.c_str());
    } else {
        WPEFramework::Crypto::SHA256 calculator; 
        ASSERT(hashLength == calculator.Length);
        
        if (hashLength == calculator.Length) {
            calculator.Input(dataBuffer.Buffer(), dataBuffer.Size());

            const uint8_t* fileHash = calculator.Result();
            
            ::memcpy(hash, fileHash, calculator.Length);

            result = true;
        } else {
            fprintf(stderr,"Output hash buffer has a incorrect size(%d), need %d bytes", hashLength, calculator.Length);
        }
    }

    return result;
}


namespace CDMi {

DRM_WCHAR* createDrmWchar(std::string const& s) {
    DRM_WCHAR* w = new DRM_WCHAR[s.length() + 1];
    for (size_t i = 0; i < s.length(); ++i)
        w[i] = DRM_ONE_WCHAR(s[i], '\0');
    w[s.length()] = DRM_ONE_WCHAR('\0', '\0');
    return w;
}

void PackedCharsToNative(DRM_CHAR *f_pPackedString, DRM_DWORD f_cch) {
    DRM_DWORD ich = 0;

    if( f_pPackedString == nullptr
     || f_cch == 0 )
    {
        return;
    }
    for( ich = 1; ich <= f_cch; ich++ )
    {
        f_pPackedString[f_cch - ich] = ((DRM_BYTE*)f_pPackedString)[ f_cch - ich ];
    }
}

std::string GetDrmStorePath()
{
    const uint32_t MAXLEN = 256;
    char pathStr[MAXLEN];
    if (g_dstrCDMDrmStoreName.cchString >= MAXLEN)
        return "";
    DRM_UTL_DemoteUNICODEtoASCII(g_dstrCDMDrmStoreName.pwszString,
            pathStr, MAXLEN);
    ((DRM_BYTE*)pathStr)[g_dstrCDMDrmStoreName.cchString] = 0;
    PackedCharsToNative(pathStr, g_dstrCDMDrmStoreName.cchString + 1);

    return string(pathStr);
}

class PlayReady : public IMediaKeys, public IMediaKeysExt {
private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

    class Config : public Core::JSON::Container {
    public:
        Config(const Config&) = delete;
        Config& operator=(const Config&) = delete;
        Config()
            : Core::JSON::Container()
            , MeteringCertificate()
            , CertificateLabel()
        {
            Add(_T("metering"), &MeteringCertificate);
            Add(_T("certificatelabel"), &CertificateLabel);
        }
        ~Config()
        {
        }

    public:
        Core::JSON::String MeteringCertificate;
        Core::JSON::String CertificateLabel;
    };

public:
    PlayReady() :
       m_poAppContext(nullptr)
       , m_meteringCertificate(nullptr)
       , m_meteringCertificateSize(0) {
    }

    ~PlayReady(void) {
        if (m_poAppContext)
            Drm_Uninitialize(m_poAppContext.get());

        if (m_meteringCertificate != nullptr) {
            delete [] m_meteringCertificate;
            m_meteringCertificate = nullptr;
        }
    }

    CDMi_RESULT CreateMediaKeySession(
        const std::string & keySystem,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession) {

        bool isNetflixPlayready = (strstr(keySystem.c_str(), "netflix") != nullptr);
        if (isNetflixPlayready) {
           // TODO: why is the order different when dealing with netflix?
           *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbCDMData, f_cbCDMData, f_pbInitData, f_cbInitData, m_poAppContext.get(), !isNetflixPlayready);
        } else {
           *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData, f_pbCDMData, f_cbCDMData, m_poAppContext.get(), !isNetflixPlayready);
        }
 
        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    virtual CDMi_RESULT GetMetrics(std::string& metrics) {
        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {
        SafeCriticalSection systemLock(drmAppContextMutex_);
        // MediaKeySession * mediaKeySession = dynamic_cast<MediaKeySession *>(f_piMediaKeySession);
        // ASSERT((mediaKeySession != nullptr) && "Expected a locally allocated MediaKeySession");

        delete f_piMediaKeySession;
        return CDMi_SUCCESS; 
    }

    ////////////////////
    // Ext
    ////////////////////
    uint64_t GetDrmSystemTime() const override
    {
        fprintf(stderr, "%s:%d: PR is asked for system time\n", __FILE__, __LINE__);

        // Playready version > 3 supports client time completely within the opaque blobs sent
        // between the Playready client and server, so this function should really
        // not have to return a real time. However, the Netflix server still needs
        // a good client time for legacy reasons.
        // In this reference DPI we are cheating my just returning the linux system
        // time. A real implementation would be more complicated, perhaps getting
        // time from some sort of secure and/or anti-rollback resource.
        
        // return static_cast<uint64_t>(time(NULL));

               SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
       DRM_UINT64 utctime64;
       DRM_RESULT err = Drm_Clock_GetSystemTime(m_poAppContext.get(), &utctime64);
       if (err != DRM_SUCCESS) {
           fprintf(stderr,"Error: Drm_Clock_GetSystemTime returned 0x%lX\n", (long)err);
           // return invalid time
           return static_cast<uint64_t>(-1);
       } else {
           return static_cast<uint64_t>(utctime64);
       }
#endif

       return 0;
    }

    std::string GetVersionExt() const override
    {
        const uint32_t MAXLEN = 64;
        char versionStr[MAXLEN];
        if (g_dstrReqTagPlayReadyClientVersionData.cchString >= MAXLEN)
            return "";
        DRM_UTL_DemoteUNICODEtoASCII(g_dstrReqTagPlayReadyClientVersionData.pwszString,
                versionStr, MAXLEN);
        ((DRM_BYTE*)versionStr)[g_dstrReqTagPlayReadyClientVersionData.cchString] = 0;
        PackedCharsToNative(versionStr, g_dstrReqTagPlayReadyClientVersionData.cchString + 1);

        return string(versionStr);
    }

    uint32_t GetLdlSessionLimit() const override
    {
        // return NONCE_STORE_SIZE;
        SafeCriticalSection lock(drmAppContextMutex_);

        ASSERT(m_poAppContext.get() != nullptr);

        uint32_t ldlLimit = 0;
#ifdef NETFLIX
        DRM_RESULT err = Drm_LicenseAcq_GetLdlSessionsLimit_Netflix(m_poAppContext.get(), &ldlLimit);
        if (err != DRM_SUCCESS) {
            fprintf(stderr,"Error: Drm_LicenseAcq_GetLdlSessionsLimit_Netflix returned 0x%lX\n", (long)err);
            return 0;
        }
#endif

        return ldlLimit;
    }

    bool IsSecureStopEnabled() override
    {
        // method not used for Playready version > 3
        // return true;

        SafeCriticalSection lock(drmAppContextMutex_);
#ifdef NETFLIX
        return static_cast<bool>(Drm_SupportSecureStop());
#else
        return false;
#endif
    }

    CDMi_RESULT EnableSecureStop(VARIABLE_IS_NOT_USED bool enable) override
    {
        // method not used for Playready version > 3
        // return CDMi_SUCCESS;

        SafeCriticalSection lock(drmAppContextMutex_);
#ifdef NETFLIX
        Drm_TurnSecureStop(static_cast<int>(enable));
#endif

        return CDMi_SUCCESS;
    }

    uint32_t ResetSecureStops() override
    {
        // method not used for Playready version > 3
        // return 0;

        SafeCriticalSection lock(drmAppContextMutex_);
        // if secure stop is not supported, return
        DRM_WORD numDeleted = 0;
#ifdef NETFLIX
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return 0;

        DRM_RESULT err = Drm_ResetSecureStops(m_poAppContext.get(), &numDeleted);
        if (err != DRM_SUCCESS) {
            fprintf(stderr,"Drm_ResetSecureStops returned 0x%lx\n", (long)err);
        }
#endif
        return numDeleted;        
    }


   CDMi_RESULT GetSecureStopIds(uint8_t ids[], uint16_t, uint32_t & count)
    {
        // SafeCriticalSection lock(drmAppContextMutex_);
        // CDMi_RESULT cr = CDMi_SUCCESS;

        // DRM_ID *ssSessionIds = nullptr;

        // DRM_RESULT dr;
        // dr = Drm_SecureStop_EnumerateSessions(
        //         m_poAppContext.get(),
        //         m_meteringCertificateSize, //playready3MeteringCertSize,
        //         m_meteringCertificate,     //playready3MeteringCert,
        //         &count,
        //         &ssSessionIds);

        // if (dr != DRM_SUCCESS && dr != DRM_E_NOMORE) {
        //     fprintf(stderr, "Error in Drm_SecureStop_EnumerateSessions (error: 0x%08X)", static_cast<unsigned int>(dr));
        //     cr = CDMi_S_FALSE;
        // } else {
        //     for (uint32_t i = 0; i < count; ++i)
        //     {
        //         ASSERT(sizeof(ssSessionIds[i].rgb) == DRM_ID_SIZE);
        //         memcpy(&ids[i * DRM_ID_SIZE], ssSessionIds[i].rgb, DRM_ID_SIZE);
        //     }

        //     if (count) {
        //         fprintf(stderr, "Found %d pending secure stop%s", count, (count > 1) ? "s" : "");
        //     }
        // }

        // SAFE_OEM_FREE(ssSessionIds);

        // return cr;

        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        // if secure stop is not supported, return NotAllowed
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return CDMi_SUCCESS;

        DRM_BYTE sessionIds[TEE_MAX_NUM_SECURE_STOPS][TEE_SESSION_ID_LEN];
        DRM_RESULT err = Drm_GetSecureStopIds(m_poAppContext.get(), sessionIds, &count);
        if (err != DRM_SUCCESS) {
            fprintf(stderr,"Drm_GetSecureStopIds returned 0x%lx\n", (long)err);
            return CDMi_S_FALSE;
        }

        for (int i = 0; i < count; ++i) {
            memcpy(&ids[i * TEE_SESSION_ID_LEN], sessionIds[i], TEE_SESSION_ID_LEN);
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            uint8_t * rawData,
            uint16_t & rawSize)
    {
        // SafeCriticalSection lock(drmAppContextMutex_);
        // CDMi_RESULT cr = CDMi_SUCCESS;

        // // Get the secure stop challenge
        // DRM_ID ssSessionDrmId;
        // ASSERT(sizeof(ssSessionDrmId.rgb) >= sessionIDLength);
        // memcpy(ssSessionDrmId.rgb, sessionID, sessionIDLength);

        // DRM_DWORD ssChallengeSize;
        // DRM_BYTE *ssChallenge;

        // DRM_RESULT dr = Drm_SecureStop_GenerateChallenge(
        //         m_poAppContext.get(),
        //         &ssSessionDrmId,
        //         m_meteringCertificateSize, //playready3MeteringCertSize,
        //         m_meteringCertificate,     //playready3MeteringCert,
        //         0, nullptr, // no custom data
        //         &ssChallengeSize,
        //         &ssChallenge);

        // if (dr != DRM_SUCCESS) {
        //     fprintf(stderr, "Error in Drm_SecureStop_GenerateChallenge (error: 0x%08X)", static_cast<unsigned int>(dr));
        //     cr = CDMi_S_FALSE;
        // } else {
        //     if((rawData != nullptr) && (rawSize >= ssChallengeSize)){
        //         memcpy(rawData, ssChallenge, ssChallengeSize);
        //     }
        //     rawSize = ssChallengeSize;
        // }

        // return cr;

                SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        // if secure stop is not supported, return
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return CDMi_SUCCESS;

        if (!sessionIDLength) {
            fprintf(stderr,"Drm_GetSecureStop sessionID length %zu", sessionIDLength);
            return CDMi_S_FALSE;
        }

        // convert our vector to the uuid, sessionID is only supposed to be 16 bytes long
        uint8_t uuid[TEE_SESSION_ID_LEN];
        memcpy(&uuid[0], &sessionID[0], TEE_SESSION_ID_LEN);

        // PlayReady doesn't like valid pointer + size 0
        DRM_BYTE* passedRawData = static_cast<DRM_BYTE*>(rawData);
        DRM_RESULT err = Drm_GetSecureStop(m_poAppContext.get(), uuid, passedRawData, &rawSize);
        if (err != DRM_E_BUFFERTOOSMALL) {
            fprintf(stderr,"Drm_GetSecureStop(0) returned 0x%lx\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT CommitSecureStop(
            const uint8_t sessionID[],
            uint32_t sessionIDLength,
            const uint8_t serverResponse[],
            uint32_t serverResponseLength) override
    {
        // SafeCriticalSection lock(drmAppContextMutex_);
        // CDMi_RESULT cr = CDMi_SUCCESS;

        // if (sessionIDLength == 0) {
        //     fprintf(stderr, "Error: empty session id");
        //     cr = CDMi_S_FALSE;
        // }
        // if (serverResponseLength  == 0) {
        //     cr = CDMi_S_FALSE;
        // }

        // if (cr == CDMi_SUCCESS){
        //     DRM_ID sessionDrmId;
        //     ASSERT(sizeof(sessionDrmId.rgb) >= sessionIDLength);
        //     memcpy(sessionDrmId.rgb, sessionID, sessionIDLength);

        //     DRM_DWORD customDataSizeBytes = 0;
        //     DRM_CHAR *pCustomData = NULL;

        //     DRM_RESULT dr;
        //     dr = Drm_SecureStop_ProcessResponse(
        //         m_poAppContext.get(),
        //         &sessionDrmId,
        //         m_meteringCertificateSize, //playready3MeteringCertSize,
        //         m_meteringCertificate,     //playready3MeteringCert,
        //         serverResponseLength,
        //         serverResponse,
        //         &customDataSizeBytes,
        //         &pCustomData);
        //     if (dr == DRM_SUCCESS) {
        //         fprintf(stderr, "secure stop commit successful");
        //         if (pCustomData && customDataSizeBytes)
        //         {
        //             // We currently don't use custom data from the server. Just log here.
        //             std::string customDataStr(pCustomData, customDataSizeBytes);
        //             fprintf(stderr, "custom data = \"%s\"", customDataStr.c_str());
        //         }
        //     }
        //     else {
        //         fprintf(stderr, "Drm_SecureStop_ProcessResponse returned 0x%lx", static_cast<unsigned long>(dr));
        //     }

        //     SAFE_OEM_FREE(pCustomData);
        // }

        // return cr;

                SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        // if secure stop is not supported, return
        DRM_BOOL supported = Drm_SupportSecureStop();
        if (supported == FALSE)
            return CDMi_SUCCESS;

        if (!sessionIDLength) {
            fprintf(stderr,"Warning: sessionIDLength is zero.\n");
            return CDMi_INVALID_ARG;
        }


        // convert our vector to the uuid, sessionID is only supposed to be 16 bytes long
        uint8_t uuid[TEE_SESSION_ID_LEN];
        memcpy(&uuid[0], &sessionID[0], TEE_SESSION_ID_LEN);

        // commit it
        DRM_RESULT err = Drm_CommitSecureStop(m_poAppContext.get(), uuid);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr,"Drm_CommitSecureStop returned 0x%lx\n", (long)err);
        }
#endif

        return CDMi_SUCCESS;

    }

    CDMi_RESULT DeleteKeyStore() override
    {
        // There is no keyfile in PlayReady version > 3, so we cannot implement this function.
        // return CDMi_SUCCESS;

                SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        DRM_RESULT err = Drm_DeleteKeyStore();
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr,"Error: Drm_DeleteKeyStore returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;

    }

    CDMi_RESULT DeleteSecureStore() override
    {
        // SafeCriticalSection lock(drmAppContextMutex_);

        // if (remove(m_storeLocation.c_str()) != 0) {
        //     fprintf(stderr, "Error removing DRM store file");
        // }

        // return CDMi_SUCCESS;

            SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        DRM_RESULT err = Drm_DeleteSecureStore(&drmStore_);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr,"Error: Drm_DeleteSecureStore returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;
    }

    CDMi_RESULT GetKeyStoreHash(
            VARIABLE_IS_NOT_USED uint8_t keyStoreHash[],
            VARIABLE_IS_NOT_USED uint32_t keyStoreHashLength) override
    {

        // There is no keyfile in PlayReady version > 3, so we cannot implement this function.
        // return CDMi_SUCCESS;

        SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        if (keyStoreHashLength < 256)
        {
            fprintf(stderr,"Error: opencdm_get_secure_store_hash needs an array of size 256\n");
            return CDMi_S_FALSE;
        }

        DRM_RESULT err = Drm_GetKeyStoreHash(keyStoreHash);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr,"Error: Drm_GetSecureStoreHash returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;

    }

    CDMi_RESULT GetSecureStoreHash(
            uint8_t secureStoreHash[],
            uint32_t secureStoreHashLength) override
    {
        // SafeCriticalSection lock(drmAppContextMutex_);

        // if (calcFileSha256(m_storeLocation, secureStoreHash, secureStoreHashLength) == false)
        // {
        //     fprintf(stderr, "Error: calcFileSha256 failed");
        //     return CDMi_S_FALSE;
        // }
        // return CDMi_SUCCESS;

            SafeCriticalSection lock(drmAppContextMutex_);

#ifdef NETFLIX
        if (secureStoreHashLength < 256)
        {
            fprintf(stderr,"Error: opencdm_get_secure_store_hash needs an array of size 256\n");
            return CDMi_S_FALSE;
        }

        DRM_RESULT err = Drm_GetSecureStoreHash(&drmStore_, secureStoreHash);
        if (err != DRM_SUCCESS)
        {
            fprintf(stderr,"Error: Drm_GetSecureStoreHash returned 0x%lX\n", (long)err);
            return CDMi_S_FALSE;
        }
#endif

        return CDMi_SUCCESS;
    }

    void Initialize(const WPEFramework::PluginHost::IShell * shell, const std::string&  configline)
    {
        // string persistentPath = shell->PersistentPath();
        // string statePath = persistentPath + "/state"; // To store rollback clock state etc
        // m_readDir = persistentPath + "/playready";
        // m_storeLocation = persistentPath + "/playready/storage/drmstore";
       
        // Config config;
        // config.FromString(configline);

        // if (config.MeteringCertificate.IsSet() == true) {
        //     Core::DataElementFile dataBuffer(config.MeteringCertificate.Value(), Core::File::USER_READ | Core::File::GROUP_READ);

        //     if(dataBuffer.IsValid() == false) {
        //         TRACE_L1(_T("Failed to open %s"), config.MeteringCertificate.Value().c_str());
        //     } else {
        //         m_meteringCertificateSize = dataBuffer.Size();
        //         m_meteringCertificate     = new DRM_BYTE[m_meteringCertificateSize];

        //         ::memcpy(m_meteringCertificate, dataBuffer.Buffer(), dataBuffer.Size());
        //     }
        // }

        // if ((config.CertificateLabel.IsSet() == true) && (config.CertificateLabel.Value().empty() == false)) {
        //     Core::SystemInfo::SetEnvironment(_T("PLAYREADY_CERTIFICATE_LABEL"), config.CertificateLabel.Value());
        // }

        // Core::Directory stateDir(statePath.c_str());
        // stateDir.Create();

        // Core::SystemInfo::SetEnvironment(_T("HOME"), statePath);

        // ASSERT(m_poAppContext.get() == nullptr);

        // std::string rdir(m_readDir);

        // // Create wchar strings from the arguments.
        // drmdir_ = createDrmWchar(rdir);

        // // Initialize Ocdm directory.
        // g_dstrDrmPath.pwszString = drmdir_;
        // g_dstrDrmPath.cchString = rdir.length();

        // // Store store location
        // std::string store(m_storeLocation);

        // drmStore_.pwszString = createDrmWchar(store);
        // drmStore_.cchString = store.length();

        // // Init opaque buffer.
        // appContextOpaqueBuffer_ = new DRM_BYTE[MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE];

        // // Init revocation buffer.
        // pbRevocationBuffer_ = new DRM_BYTE[REVOCATION_BUFFER_SIZE];

        // //return CDMi_SUCCESS;

        // // TODO: this is just a move from InitSystemExt
        // SafeCriticalSection lock(drmAppContextMutex_);

        // DRM_RESULT err;

        // // DRM Platform Initialization
        // err = Drm_Platform_Initialize(nullptr);
        // if(DRM_FAILED(err))
        // {
        //     fprintf(stderr, "Error in Drm_Platform_Initialize: 0x%08lX\n", err);
        //     //return CDMi_S_FALSE;
        //     return;
        // }

        // std::unique_ptr<DRM_APP_CONTEXT> appCtx;
        // appCtx.reset(new DRM_APP_CONTEXT);

        // memset(appCtx.get(), 0, sizeof(DRM_APP_CONTEXT));
        // err  = Drm_Initialize(appCtx.get(), nullptr,
        //                       appContextOpaqueBuffer_,
        //                       MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
        //                       &drmStore_);
        // if(DRM_FAILED(err)) {
        //     fprintf(stderr, "Error in Drm_Initialize: 0x%08lX\n", err);
        //     //return CDMi_S_FALSE;
        //     return;
        // }

        // m_poAppContext.swap(appCtx);
        // err = Drm_Revocation_SetBuffer(m_poAppContext.get(), pbRevocationBuffer_, REVOCATION_BUFFER_SIZE);
        // if(DRM_FAILED(err))
        // {
        //     fprintf(stderr, "Error in Drm_Revocation_SetBuffer: 0x%08lX\n", err);
        //     //return CDMi_S_FALSE;
        //     return;
        // }

        // //return CDMi_SUCCESS;


        string persistentPath = shell->PersistentPath();
        string statePath = persistentPath + "state"; // To store rollback clock state etc
        string storePath = persistentPath + "playready/storage";
        m_readDir = persistentPath + "playready";
        m_storeLocation = persistentPath + "playready/storage/drmstore";

        Core::Directory storeDir(storePath.c_str());
        storeDir.CreatePath();
        Core::Directory stateDir(statePath.c_str());
        stateDir.Create();

        Core::SystemInfo::SetEnvironment(_T("HOME"), statePath);

        ASSERT(m_poAppContext.get() == nullptr);

        std::string rdir(m_readDir);

        // Create wchar strings from the arguments.
        drmdir_ = createDrmWchar(rdir);

        // Initialize Ocdm directory.
        g_dstrDrmPath.pwszString = drmdir_;
        g_dstrDrmPath.cchString = rdir.length();

        // Store store location
        std::string store(m_storeLocation);

        g_dstrCDMDrmStoreName.pwszString = createDrmWchar(store);
        g_dstrCDMDrmStoreName.cchString = store.length();

        // Init opaque buffer.
        appContextOpaqueBuffer_ = new DRM_BYTE[MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE];

        // Init revocation buffer.
        pbRevocationBuffer_ = new DRM_BYTE[REVOCATION_BUFFER_SIZE];

        //return CDMi_SUCCESS;

        // TODO: this is just a move from InitSystemExt
        SafeCriticalSection lock(drmAppContextMutex_);

        DRM_RESULT err;

        // DRM Platform Initialization
#ifdef PR_4_4
        err = Drm_Platform_Initialize(nullptr);
#else
        err = Drm_Platform_Initialize();
#endif
        if (DRM_FAILED(err))
        {
            fprintf(stderr,"Error in Drm_Platform_Initialize: 0x%08lX\n", err);
            //return CDMi_S_FALSE;
            return;
        }

        std::unique_ptr<DRM_APP_CONTEXT> appCtx;
        appCtx.reset(new DRM_APP_CONTEXT);

        memset(appCtx.get(), 0, sizeof(DRM_APP_CONTEXT));
        err  = Drm_Initialize(appCtx.get(), nullptr,
                              appContextOpaqueBuffer_,
                              MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                              &g_dstrCDMDrmStoreName);
        if ((err == DRM_E_SECURESTOP_STORE_CORRUPT) || \
                (err == DRM_E_SECURESTORE_CORRUPT) || \
                (err == DRM_E_DST_CORRUPTED)){

            fprintf(stderr,"%s:%d drmstore corrrupt, delete it !!!!\n", __FUNCTION__, __LINE__);
            //if drmstore file is corrupted, remove it and init again, playready will create a new one
            remove(GetDrmStorePath().c_str());

            err  = Drm_Initialize(appCtx.get(), nullptr,
                    appContextOpaqueBuffer_,
                    MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE,
                    &g_dstrCDMDrmStoreName);
        }
        if (DRM_FAILED(err)) {
            fprintf(stderr,"Error in Drm_Initialize: 0x%08lX\n", err);
            //return CDMi_S_FALSE;
            return;
        }

        m_poAppContext.swap(appCtx);
        err = Drm_Revocation_SetBuffer(m_poAppContext.get(), pbRevocationBuffer_, REVOCATION_BUFFER_SIZE);
        if (DRM_FAILED(err))
        {
            fprintf(stderr,"Error in Drm_Revocation_SetBuffer: 0x%08lX\n", err);
            //return CDMi_S_FALSE;
            return;
        }

        //return CDMi_SUCCESS;
    }

private:
    DRM_WCHAR* drmdir_;
    DRM_CONST_STRING drmStore_;

    DRM_BYTE *appContextOpaqueBuffer_ = nullptr;
    DRM_BYTE *pbRevocationBuffer_ = nullptr;
    std::unique_ptr<DRM_APP_CONTEXT> m_poAppContext;

    string m_readDir;
    string m_storeLocation;

    DRM_BYTE* m_meteringCertificate;
    uint32_t m_meteringCertificateSize;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
