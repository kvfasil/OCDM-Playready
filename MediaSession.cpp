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

#include "MediaSession.h"
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <string.h>
#include <vector>
#include <sys/utsname.h>
//#include <core/core.h>
#include "gst_svp_meta.h"

using namespace WPEFramework;
using SafeCriticalSection = Core::SafeSyncType<Core::CriticalSection>;
MODULE_NAME_DECLARATION(BUILD_REFERENCE);

extern Core::CriticalSection drmAppContextMutex_;
extern DRM_CONST_STRING g_dstrCDMDrmStoreName;

#define NYI_KEYSYSTEM "keysystem-placeholder"

#ifdef DRM_WCHAR_CAST
#define WCHAR_CAST DRM_WCHAR_CAST
#endif

#ifdef DRM_CREATE_DRM_STRING
#define CREATE_DRM_STRING DRM_CREATE_DRM_STRING
#endif

#ifdef DRM_EMPTY_DRM_STRING
#define EMPTY_DRM_STRING DRM_EMPTY_DRM_STRING
#endif

#ifdef DRM_NO_OF
#define NO_OF DRM_NO_OF
#endif

using namespace std;

namespace CDMi {

const DRM_CONST_STRING *g_rgpdstrRights[1] = {&g_dstrDRM_RIGHT_PLAYBACK};

void * MediaKeySession::sess = NULL;
uint32_t MediaKeySession::m_secCount = 0;

// Parse out the first PlayReady initialization header found in the concatenated
// block of headers in _initData_.
// If a PlayReady header is found, this function returns true and the header
// contents are stored in _output_.
// Otherwise, returns false and _output_ is not touched.
bool parsePlayreadyInitializationData(const std::string& initData, std::string* output)
{
    BufferReader input(reinterpret_cast<const uint8_t*>(initData.data()), initData.length());

    static const uint8_t playreadySystemId[] = {
      0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86,
      0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F, 0x95,
    };

    // one PSSH box consists of:
    // 4 byte size of the atom, inclusive.  (0 means the rest of the buffer.)
    // 4 byte atom type, "pssh".
    // (optional, if size == 1) 8 byte size of the atom, inclusive.
    // 1 byte version, value 0 or 1.  (skip if larger.)
    // 3 byte flags, value 0.  (ignored.)
    // 16 byte system id.
    // (optional, if version == 1) 4 byte key ID count. (K)
    // (optional, if version == 1) K * 16 byte key ID.
    // 4 byte size of PSSH data, exclusive. (N)
    // N byte PSSH data.
    while (!input.IsEOF()) {
      size_t startPosition = input.pos();

      // The atom size, used for skipping.
      uint64_t atomSize;

      if (!input.Read4Into8(&atomSize)) {
        return false;
      }

      std::vector<uint8_t> atomType;
      if (!input.ReadVec(&atomType, 4)) {
          return false;
      }

      if (atomSize == 1) {
          if (!input.Read8(&atomSize)) {
              return false;
          }
      } else if (atomSize == 0) {
        atomSize = input.size() - startPosition;
      }

      if (memcmp(&atomType[0], "pssh", 4)) {
          if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
            return false;
          }
          continue;
      }

      uint8_t version;
      if (!input.Read1(&version)) {
          return false;
      }


      if (version > 1) {
        // unrecognized version - skip.
        if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
          return false;
        }
        continue;
      }

      // flags
      if (!input.SkipBytes(3)) {
        return false;
      }

      // system id
      std::vector<uint8_t> systemId;
      if (!input.ReadVec(&systemId, sizeof(playreadySystemId))) {
        return false;
      }

      if (memcmp(&systemId[0], playreadySystemId, sizeof(playreadySystemId))) {
        // skip non-Playready PSSH boxes.
        if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
          return false;
        }
        continue;
      }

      if (version == 1) {
        // v1 has additional fields for key IDs.  We can skip them.
        uint32_t numKeyIds;
        if (!input.Read4(&numKeyIds)) {
          return false;
        }

        if (!input.SkipBytes(numKeyIds * 16)) {
          return false;
        }
      }

      // size of PSSH data
      uint32_t dataLength;
      if (!input.Read4(&dataLength)) {
        return false;
      }

      output->clear();
      if (!input.ReadString(output, dataLength)) {
        return false;
      }

      return true;
  }

  // we did not find a matching record
  return false;
}

MediaKeySession::MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData, const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, DRM_APP_CONTEXT * poAppContext, bool initiateChallengeGeneration /* = false */)
    : m_pbOpaqueBuffer(nullptr)
    , m_cbOpaqueBuffer(0)
    , m_pbRevocationBuffer(nullptr)
    , m_eKeyState(KEY_INIT)
    , m_pbChallenge(nullptr)
    , m_cbChallenge(0)
    , m_pchSilentURL(nullptr)
    , m_customData(reinterpret_cast<const char*>(f_pbCDMData), f_cbCDMData)
    , m_piCallback(nullptr)
    , mSessionId(0)
    , m_fCommit(FALSE)
    , mInitiateChallengeGeneration(initiateChallengeGeneration)
    , m_poAppContext(poAppContext)
    , m_oDecryptContext(nullptr)
    , m_oDecryptContext2(nullptr)
    , m_decryptInited(false)
    , m_pSVPContext(NULL)
    , m_rpcID(0)
{
   memset(&levels_, 0, sizeof(levels_));
   DRM_RESULT dr = DRM_SUCCESS;

   ocdm_log("Initializing SVP context for client side\n");
   gst_svp_ext_get_context(&m_pSVPContext, Client, m_rpcID);

   if (!initiateChallengeGeneration) {
      mLicenseResponse = std::unique_ptr<LicenseResponse>(new LicenseResponse());
      mSecureStopId.clear();

      // TODO: can we do this nicer?
      mDrmHeader.resize(f_cbCDMData);
      memcpy(&mDrmHeader[0], f_pbCDMData, f_cbCDMData);
      m_secCount++;
   } else {
      m_oDecryptContext = new DRM_DECRYPT_CONTEXT;
      memset(m_oDecryptContext, 0, sizeof(DRM_DECRYPT_CONTEXT));
      m_oDecryptContext2 = new DRM_DECRYPT_CONTEXT;
      memset(m_oDecryptContext2, 0, sizeof(DRM_DECRYPT_CONTEXT));

      DRM_ID oSessionID;

      DRM_DWORD cchEncodedSessionID = SIZEOF(m_rgchSessionID);

      // FIXME: Change the interface of this method? Not sure why the win32 bondage is still so popular.
      std::string initData(reinterpret_cast<const char*>(f_pbInitData), f_cbInitData);
      std::string playreadyInitData;

      ocdm_log("Constructing PlayReady Session [%p]\n", this);

      ChkMem(m_pbOpaqueBuffer = (DRM_BYTE *)Oem_MemAlloc(MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE));
      m_cbOpaqueBuffer = MINIMUM_APPCONTEXT_OPAQUE_BUFFER_SIZE;
#ifndef REUSE_APPCONTEXT
      ChkMem(m_poAppContext = (DRM_APP_CONTEXT *)Oem_MemAlloc(SIZEOF(DRM_APP_CONTEXT)));

      // Initialize DRM app context.
      dr = Drm_Initialize(m_poAppContext,
                           nullptr,
                           m_pbOpaqueBuffer,
                           m_cbOpaqueBuffer,
                           &g_dstrCDMDrmStoreName);
      if ((dr == DRM_E_SECURESTOP_STORE_CORRUPT) || \
              (dr == DRM_E_SECURESTORE_CORRUPT) || \
              (dr == DRM_E_DST_CORRUPTED)){

          ocdm_log( "%s:%d drmstore corrrupt, delete it !!!!\n", __FUNCTION__, __LINE__);
          //if drmstore file is corrupted, remove it and init again, playready will create a new one
          remove(GetDrmStorePath().c_str());

          dr = Drm_Initialize(m_poAppContext,
                  nullptr,
                  m_pbOpaqueBuffer,
                  m_cbOpaqueBuffer,
                  &g_dstrCDMDrmStoreName);
      }
      ChkDR(dr);
      if (DRM_REVOCATION_IsRevocationSupported()) {
         ChkMem(m_pbRevocationBuffer = (DRM_BYTE *)Oem_MemAlloc(REVOCATION_BUFFER_SIZE));

         ChkDR(Drm_Revocation_SetBuffer(m_poAppContext,
                                       m_pbRevocationBuffer,
                                       REVOCATION_BUFFER_SIZE));
      }
#endif

#ifdef PR_4_4
      //temporary hack to allow time based licenses
      ( DRM_REINTERPRET_CAST( DRM_APP_CONTEXT_INTERNAL, m_poAppContext ) )->fClockSet = TRUE;
#endif

      // Generate a random media session ID.
      ChkDR(Oem_Random_GetBytes(nullptr, (DRM_BYTE *)&oSessionID, SIZEOF(oSessionID)));
      ZEROMEM(m_rgchSessionID, SIZEOF(m_rgchSessionID));

      // Store the generated media session ID in base64 encoded form.
      ChkDR(DRM_B64_EncodeA((DRM_BYTE *)&oSessionID,
                              SIZEOF(oSessionID),
                              m_rgchSessionID,
                              &cchEncodedSessionID,
                              0));

      // The current state MUST be KEY_INIT otherwise error out.
      ChkBOOL(m_eKeyState == KEY_INIT, DRM_E_INVALIDARG);

      if (!parsePlayreadyInitializationData(initData, &playreadyInitData)) {
            playreadyInitData = initData;
      }
      ChkDR(Drm_Content_SetProperty(m_poAppContext,
                                    DRM_CSP_AUTODETECT_HEADER,
                                    reinterpret_cast<const DRM_BYTE*>(playreadyInitData.data()),
                                    playreadyInitData.size()));

      // The current state MUST be KEY_INIT otherwise error out.
      ChkBOOL(m_eKeyState == KEY_INIT, DRM_E_INVALIDARG);
      m_secCount++;
      return;
   }

ErrorExit:
  if (DRM_FAILED(dr)) {
    const DRM_CHAR* description;
    DRM_ERR_GetErrorNameFromCode(dr, &description);
    ocdm_log("playready error1: %s\n", description);
  }
}

MediaKeySession::~MediaKeySession(void) {
  gst_svp_ext_free_context(m_pSVPContext);
  Close();
  if (--m_secCount == 0) {
    svp_release_secure_buffers(m_pSVPContext, sess, nullptr, nullptr, 0); // Secure_V2_SessionDestroy(&sess);
  }
  sess = NULL;
  ocdm_log("Destructing PlayReady Session [%p]\n", this);
}

const char *MediaKeySession::GetSessionId(void) const {
  return m_rgchSessionID;
}

const char *MediaKeySession::GetKeySystem(void) const {
  return NYI_KEYSYSTEM; // FIXME : replace with keysystem and test.
}

DRM_RESULT DRM_CALL MediaKeySession::_PolicyCallback(
    const DRM_VOID *f_pvOutputLevelsData,
    DRM_POLICY_CALLBACK_TYPE f_dwCallbackType,
#ifdef PR_4_4
    const DRM_KID *f_pKID,
    const DRM_LID *f_pLID,
#endif
    const DRM_VOID *f_pv) {
  return DRM_SUCCESS;
}

void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {

  if (f_piMediaKeySessionCallback) {
    m_piCallback = const_cast<IMediaKeySessionCallback *>(f_piMediaKeySessionCallback);

    if (mInitiateChallengeGeneration) {
      playreadyGenerateKeyRequest();
    }
  } else {
      m_piCallback = nullptr;
  }
}

bool MediaKeySession::playreadyGenerateKeyRequest() {

  DRM_RESULT dr = DRM_SUCCESS;
  DRM_DWORD cchSilentURL = 0;

#ifdef PR_4_4
  dr = Drm_Reader_Bind(m_poAppContext,
                        g_rgpdstrRights,
                        DRM_NO_OF(g_rgpdstrRights),
                        _PolicyCallback,
                        nullptr,
                        m_oDecryptContext);
#endif

  // FIXME :  Check add case Play rights already acquired
  // Try to figure out the size of the license acquisition
  // challenge to be returned.
  dr = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                        g_rgpdstrRights,
                                        sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                        NULL,
                                        !m_customData.empty() ? m_customData.c_str() : nullptr,
                                        m_customData.size(),
                                        NULL,
                                        &cchSilentURL,
                                        NULL,
                                        NULL,
#ifdef PR_4_4
                                        m_pbChallenge,
                                        &m_cbChallenge,
                                        NULL);
#else
                                        NULL,
                                        &m_cbChallenge);
#endif
  if (dr == DRM_E_NO_URL) {
      cchSilentURL = 0;
      dr = Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                        g_rgpdstrRights,
                                        sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                        NULL,
                                        !m_customData.empty() ? m_customData.c_str() : nullptr,
                                        m_customData.size(),
                                        NULL,
                                        NULL,
                                        NULL,
                                        NULL,
#ifdef PR_4_4
                                        m_pbChallenge,
                                        &m_cbChallenge,
                                        NULL);
#else
                                        NULL,
                                        &m_cbChallenge);
#endif
  }
  if (dr == DRM_E_BUFFERTOOSMALL) {
     SAFE_OEM_FREE(m_pchSilentURL);
     ChkMem(m_pchSilentURL = (DRM_CHAR *)Oem_MemAlloc(cchSilentURL + 1));
     ZEROMEM(m_pchSilentURL, cchSilentURL + 1);

    // Allocate buffer that is sufficient to store the license acquisition
    // challenge.
    if (m_cbChallenge > 0)
      ChkMem(m_pbChallenge = (DRM_BYTE *)Oem_MemAlloc(m_cbChallenge));

    dr = DRM_SUCCESS;
  } else {
    ChkDR(dr);
  }
  ocdm_log("%s\n", m_customData.empty() ? m_customData.c_str() : nullptr);

  // Supply a buffer to receive the license acquisition challenge.
  ChkDR(Drm_LicenseAcq_GenerateChallenge(m_poAppContext,
                                         g_rgpdstrRights,
                                         sizeof(g_rgpdstrRights) / sizeof(DRM_CONST_STRING *),
                                         NULL,
                                         !m_customData.empty() ? m_customData.c_str() : nullptr,
                                         m_customData.size(),
                                         cchSilentURL > 0 ? m_pchSilentURL : NULL,
                                         cchSilentURL > 0 ? &cchSilentURL: NULL,
                                         nullptr,
                                         nullptr,
                                         m_pbChallenge,
#ifdef PR_4_4
                                         &m_cbChallenge,
                                         nullptr));
#else
                                         &m_cbChallenge));
#endif


  m_eKeyState = KEY_PENDING;
  if (m_piCallback)
        m_piCallback->OnKeyMessage((const uint8_t *) m_pbChallenge, m_cbChallenge, (char *)m_pchSilentURL);
  return true;

ErrorExit:
  if (DRM_FAILED(dr)) {
    const DRM_CHAR* description;
    DRM_ERR_GetErrorNameFromCode(dr, &description);
    ocdm_log("playready error2: %s\n", description);
    if (m_piCallback)
        m_piCallback->OnKeyMessage((const uint8_t *) "", 0, "");
  }
  return false;
}

CDMi_RESULT MediaKeySession::Load(void) {
  return CDMi_S_FALSE;
}

void MediaKeySession::SetParameter(const uint8_t * data, const uint32_t length) {
        //ocdm_log("set cbcs parameter\n");
}

void MediaKeySession::Update(const uint8_t *m_pbKeyMessageResponse, uint32_t  m_cbKeyMessageResponse) {

  DRM_RESULT dr = DRM_SUCCESS;
  DRM_DWORD decryptionMode;
  DRM_LICENSE_RESPONSE oLicenseResponse = {eUnknownProtocol, 0};
  ChkArg(m_pbKeyMessageResponse && m_cbKeyMessageResponse > 0);

  ChkDR(Drm_LicenseAcq_ProcessResponse(m_poAppContext,
                                       DRM_PROCESS_LIC_RESPONSE_SIGNATURE_NOT_REQUIRED,
#ifndef PR_4_4
                                       nullptr,
                                       nullptr,
#endif
                                       const_cast<DRM_BYTE *>(m_pbKeyMessageResponse),
                                       m_cbKeyMessageResponse,
                                       &oLicenseResponse));
  decryptionMode = OEM_TEE_DECRYPTION_MODE_HANDLE;
  dr = Drm_Content_SetProperty(m_poAppContext,
                           DRM_CSP_DECRYPTION_OUTPUT_MODE,
                           (const DRM_BYTE*)&decryptionMode,
                           sizeof decryptionMode);
  if (!DRM_SUCCEEDED(dr)) {
      ocdm_log("Drm_Content_SetProperty() failed with %lx", dr);
      goto ErrorExit;
  }

  dr = Drm_Reader_Bind(m_poAppContext,
                        g_rgpdstrRights,
                        DRM_NO_OF(g_rgpdstrRights),
                        _PolicyCallback,
                        nullptr,
                        m_oDecryptContext);
  if (!DRM_SUCCEEDED(dr)) {
      ocdm_log("Drm_Reader_Bind() MODE_HANDLE failed with %lx", dr);
      goto ErrorExit;
  }

  decryptionMode = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;
  dr = Drm_Content_SetProperty(m_poAppContext,
                           DRM_CSP_DECRYPTION_OUTPUT_MODE,
                           (const DRM_BYTE*)&decryptionMode,
                           sizeof decryptionMode);
  if (!DRM_SUCCEEDED(dr)) {
      ocdm_log("Drm_Content_SetProperty() failed with %lx", dr);
      goto ErrorExit;
  }

  dr = Drm_Reader_Bind(m_poAppContext,
                        g_rgpdstrRights,
                        DRM_NO_OF(g_rgpdstrRights),
                        _PolicyCallback,
                        nullptr,
                        m_oDecryptContext2);
  if (!DRM_SUCCEEDED(dr)) {
      ocdm_log("Drm_Reader_Bind() MODE_NOT_SECURE failed with %lx, ignore", dr);
  }

  m_eKeyState = KEY_READY;

  if (m_eKeyState == KEY_READY) {
    if (m_piCallback) {
      for (DRM_DWORD i = 0; i < oLicenseResponse.m_cAcks; ++i) {
        if (DRM_SUCCEEDED(oLicenseResponse.m_rgoAcks[i].m_dwResult)) {
            m_piCallback->OnKeyStatusUpdate("KeyUsable", oLicenseResponse.m_rgoAcks[i].m_oKID.rgb, DRM_ID_SIZE);
        }
      }
      m_piCallback->OnKeyStatusesUpdated();
    }
  }

  return;

ErrorExit:
  if (DRM_FAILED(dr)) {
    const DRM_CHAR* description;
    DRM_ERR_GetErrorNameFromCode(dr, &description);
    ocdm_log("playready error3: %s\n", description);

    m_eKeyState = KEY_ERROR;

    // The upper layer is blocked waiting for an update, let's wake it.
    if (m_piCallback) {
      for (DRM_DWORD i = 0; i < oLicenseResponse.m_cAcks; ++i) {
        m_piCallback->OnKeyStatusUpdate("KeyError", oLicenseResponse.m_rgoAcks[i].m_oKID.rgb, DRM_ID_SIZE);
      }
      m_piCallback->OnKeyStatusesUpdated();
    }
  }
  return;
}

CDMi_RESULT MediaKeySession::Remove(void) {
    return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::Close(void) {
    m_eKeyState = KEY_CLOSED;

    if (mInitiateChallengeGeneration == true) {
        if (DRM_REVOCATION_IsRevocationSupported() && m_pbRevocationBuffer != nullptr) {
            SAFE_OEM_FREE(m_pbRevocationBuffer);
            m_pbRevocationBuffer = nullptr;
        }
#ifndef REUSE_APPCONTEXT
        if (m_poAppContext != nullptr) {
            Drm_Uninitialize(m_poAppContext);
            SAFE_OEM_FREE(m_poAppContext);
            m_poAppContext = nullptr;
        }
#endif
        if (m_pbOpaqueBuffer != nullptr) {
            SAFE_OEM_FREE(m_pbOpaqueBuffer);
            m_pbOpaqueBuffer = nullptr;
        }

        if (m_oDecryptContext != nullptr) {
            Drm_Reader_Close(m_oDecryptContext);
            delete m_oDecryptContext;
            m_oDecryptContext = nullptr;
        }

        if (m_oDecryptContext2 != nullptr) {
            Drm_Reader_Close(m_oDecryptContext2);
            delete m_oDecryptContext2;
            m_oDecryptContext2 = nullptr;
        }

        if (m_pbChallenge != nullptr) {
            SAFE_OEM_FREE(m_pbChallenge);
            m_pbChallenge = nullptr;
        }

        if (m_pchSilentURL != nullptr) {
            SAFE_OEM_FREE(m_pchSilentURL);
            m_pchSilentURL = nullptr;
        }
    }

    return CDMi_SUCCESS;
}

   CDMi_RESULT MediaKeySession::Decrypt(
    uint8_t*                 inData,
    const uint32_t           inDataLength,
    uint8_t**                outData,
    uint32_t*                outDataLength,
    const SampleInfo*        sampleInfo,
    const IStreamProperties* properties)
{
    DRM_UINT64 iv_vector[2] = { 0 };
    void* pSecureToken      = nullptr;
    void *decryptedData     = nullptr;
    bool bGstSvpStatus      = false;

    SafeCriticalSection systemLock(drmAppContextMutex_);
    assert(sampleInfo->ivLength > 0);
    if (inDataLength == 0) {
        return CDMi_SUCCESS;
    }

    if (!m_oDecryptContext) {
        ocdm_log("Error: no decrypt context (yet?)\n");
        return CDMi_S_FALSE;
    }

    DRM_RESULT err = DRM_SUCCESS;
    DRM_DWORD rgdwMappings[2];
    bool bUseSVP = true;

    if ( (outDataLength == NULL) || (outData == NULL)
        || (sampleInfo->iv == NULL || sampleInfo->ivLength == 0) || (m_eKeyState != KEY_READY) ) {
        ocdm_log("Error: Decrypt - Invalid argument\n");
        return CDMi_S_FALSE;
    }

    *outDataLength = 0;
    *outData = NULL;

#ifndef PR_4_4
    if (!properties->InitLength()) {
      err = Drm_Reader_InitDecrypt(m_oDecryptContext, nullptr, 0);
    } else {
        // Initialize the decryption context for Cocktail packaged
        // content. This is a no-op for AES packaged content.
        if (inDataLength <= 15) {
            err = Drm_Reader_InitDecrypt(m_oDecryptContext, (DRM_BYTE*)inData, inDataLength);
        } else {
            err = Drm_Reader_InitDecrypt(m_oDecryptContext, (DRM_BYTE*)(inData + inDataLength - 15), inDataLength);
        }
    }
    if (DRM_FAILED(err)) {
        ocdm_log("Failed to init decrypt\n");
        return CDMi_S_FALSE;
    }
#endif

    // TODO: can be done in another way (now abusing "initWithLast15" variable)
    if (properties->InitLength()) {
      memcpy(iv_vector, sampleInfo->iv, sizeof(iv_vector));
    } else {
      unsigned char * ivDataNonConst = const_cast<unsigned char *>(sampleInfo->iv); // TODO: this is ugly
      for (uint32_t i = 0; i < 2; i++) {
        if (i << 3 >= sampleInfo->ivLength)
          break;
        NETWORKBYTES_TO_QWORD(iv_vector[i], &ivDataNonConst[i << 3], 0);
      }
    }

    CDMi::MediaType mediaType = CDMi::Unknown;

    if(properties != NULL) {
      mediaType = properties->GetMediaType();
      if(mediaType == CDMi::Audio) {
        // Audio does not use the secure path (SAP) so
        // use the inplace decryption technique.
        bUseSVP = false;
      }
    } else {
      ocdm_log("DYNAMIC_SVP_DECRYPTION parser not set! ");
    }

    DRM_DWORD regionCount[1] = { 0 };
    DRM_DWORD regionSkip[2] = { 0 };
    uint32_t opaque_buffer_size = 0;
    uint8_t *opaque_buffer = NULL;
    uint32_t subSampleCount = sampleInfo->subSampleCount;
    std::vector<DRM_DWORD> encryptedRegions;
    uint32_t inputLen = inDataLength - svp_token_size() - gst_svp_header_size(NULL);
    decryptedData     = reinterpret_cast<uint8_t *>(gst_svp_header_get_start_of_data( NULL, inData ));

    regionSkip[0] = sampleInfo->pattern.encrypted_blocks;
    regionSkip[1] = sampleInfo->pattern.clear_blocks;
    if (subSampleCount > 0) {
      for (int i = 0; i < subSampleCount; i++) {
        encryptedRegions.push_back(sampleInfo->subSample[i].clear_bytes);
        encryptedRegions.push_back(sampleInfo->subSample[i].encrypted_bytes);
      }
    } else {
        encryptedRegions.push_back(0);
        encryptedRegions.push_back(inputLen);
      }

    regionCount[0] = encryptedRegions.size()/2;

    if (bUseSVP) {
      uint32_t e;
      Sec_OpaqueBufferHandle*   secbuf_out  = NULL;
      // err = SecBuffer_Malloc(inDataLength, &secbuf_out);
      e = svp_allocate_secure_buffers(m_pSVPContext, (void **)&secbuf_out, &sess, nullptr, inputLen);
      if (DRM_FAILED(e)) {
          ocdm_log("Failed to run SecBuffer_Malloc\n");
          return CDMi_S_FALSE;
      }

      OEM_OPTEE_SetHandle(secbuf_out->secmem_handle);
      err = Drm_Reader_DecryptMultipleOpaque(m_oDecryptContext,
          1, iv_vector, iv_vector + 1, regionCount,
          encryptedRegions.size(), &encryptedRegions[0],
          2, regionSkip,
          inputLen, (const DRM_BYTE*)decryptedData,
          &opaque_buffer_size,
          &opaque_buffer);
      if (DRM_FAILED(err)) {
          ocdm_log("Failed to run Drm_Reader_DecryptMultipleOpaque1\n");
          return CDMi_S_FALSE;
      }
      if (opaque_buffer) {
          free(opaque_buffer);
          opaque_buffer = NULL;
      }
      // ocdm_log("Drm_Reader_DecryptOpaque video ---- %p\n", secbuf_out);

      bGstSvpStatus = svp_buffer_alloc_token(&pSecureToken);
      if (!bGstSvpStatus) {
          ocdm_log("Memory alloc for token is failure\n");
          return CDMi_S_FALSE;
      }
      /* first byte will be used for encyption type - inPlace or handle */
      bGstSvpStatus = svp_buffer_to_token(m_pSVPContext, (void *)secbuf_out, pSecureToken + sizeof(uint8_t));
      if (!bGstSvpStatus) {
          ocdm_log("Buffer to Token creation is failure");
          return CDMi_S_FALSE;
      }

      *outDataLength = svp_token_size();
      *outData = (uint8_t *)inData;

      memcpy((void *)(uint8_t*)decryptedData, pSecureToken, *outDataLength);
      // Add a header to the output buffer.
      ((DRM_BYTE*)decryptedData)[0] = 1;   // 0 = inPlace, 1 = handle

      svp_buffer_free_token(pSecureToken);
      pSecureToken = NULL;

    } else {
      err = Drm_Reader_DecryptMultipleOpaque(m_oDecryptContext2,
        1, iv_vector, iv_vector + 1, regionCount,
        encryptedRegions.size(), &encryptedRegions[0],
        2, regionSkip,
        inputLen, (const DRM_BYTE*)decryptedData,
        &opaque_buffer_size,
        &opaque_buffer);
      if (DRM_FAILED(err))
      {
          ocdm_log("Failed to run Drm_Reader_DecryptMultipleOpaque2 %x\n", err);
          return CDMi_S_FALSE;
      }
      if (opaque_buffer) {
          memcpy((uint8_t *)decryptedData, opaque_buffer, opaque_buffer_size);
          free(opaque_buffer);
          opaque_buffer = NULL;
      }

      memmove((DRM_BYTE*)decryptedData + sizeof(uint8_t), decryptedData, inputLen);
      // Add a header to the output buffer.
      ((DRM_BYTE*)decryptedData)[0] = 0;   // 0 = inPlace, 1 = handle

      *outDataLength = inDataLength;
      *outData = (uint8_t *)inData;
    }

    // Call commit during the decryption of the first sample.
    if (!m_fCommit) {
        //err = Drm_Reader_Commit(m_poAppContext, &opencdm_output_levels_callback, &levels_);
        err = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, nullptr); // TODO: pass along user data
        if (DRM_FAILED(err)) {
            ocdm_log("Failed to do Reader Commit\n");
            return CDMi_S_FALSE;
        }
        m_fCommit = TRUE;
    }
    
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
    const uint8_t *f_pbSessionKey,
    uint32_t f_cbSessionKey,
    const uint32_t  f_cbClearContentOpaque,
    uint8_t  *f_pbClearContentOpaque ) {

  return CDMi_SUCCESS;

}

}  // namespace CDMi
