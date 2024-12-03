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
#include <core/core.h>
#include "secmem_ca.h"

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
{
   memset(&levels_, 0, sizeof(levels_));
   DRM_RESULT dr = DRM_SUCCESS;

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

      fprintf(stderr,"Constructing PlayReady Session [%p]\n", this);

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

          fprintf(stderr,"%s:%d drmstore corrrupt, delete it !!!!\n", __FUNCTION__, __LINE__);
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
    fprintf(stderr,"playready error1: %s\n", description);
  }
}

MediaKeySession::~MediaKeySession(void) {
  Close();
  if(--m_secCount == 0)
    Secure_V2_SessionDestroy(&sess);
  fprintf(stderr,"Destructing PlayReady Session [%p]\n", this);
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


CDMi_RESULT MediaKeySession::SecOpaqueBuffer_Malloc(uint32_t bufLength, Sec_OpaqueBufferHandle **handle) {
  CDMi_RESULT result = CDMi_S_FALSE;
  Sec_OpaqueBufferHandle *opaqueBuf = NULL;
  secmem_handle_t _handle = 0;
  uint32_t mem_available = 0;
  uint32_t handle_available = 0;
  static int trycount = 0;
  uint32_t capacity = 0;
  uint32_t setSize = 0;

  if (0 == bufLength) {
      fprintf(stderr,"Argument `length' has value of 0\n");
      goto error;
  }
  if (NULL == handle) {
      fprintf(stderr,"Argument `handle' has value of null\n");
      goto error;
  }

  opaqueBuf = (Sec_OpaqueBufferHandle*)malloc(sizeof(Sec_OpaqueBufferHandle));
  if (NULL == opaqueBuf) {
      fprintf(stderr,"malloc failed\n");
      goto error;
  }
  if (!sess) {
      CHECK_EXACT(Secure_V2_SessionCreate(&sess), CDMi_SUCCESS, error);
      capacity = Secure_GetSecmemSize();
      if (capacity <= 0)
        goto error;
      setSize = (uint32_t)(((uint32_t)(capacity >> 20) + 1) * 0.25);
      if (setSize > 4)
        setSize = 4;
      CHECK_EXACT(Secure_V2_Init(sess, 1, 3, 0, setSize), CDMi_SUCCESS, error);  //flag = 3 custom set size
  }

  do {
      CHECK_EXACT(Secure_V2_GetSecmemSize(sess, NULL, &mem_available, NULL, &handle_available), CDMi_SUCCESS, error);
      if (handle_available > 0 && bufLength < mem_available)
          break;
      else if(++trycount > 50)
          break;
      sleep(10);
  } while (1);

  CHECK_EXACT(Secure_V2_MemCreate(sess, &_handle), CDMi_SUCCESS, error);
  CHECK_EXACT(Secure_V2_MemAlloc(sess, _handle, bufLength, NULL), CDMi_SUCCESS, error);

  opaqueBuf->secmem_handle = _handle;
  opaqueBuf->dataBufSize = bufLength;
  *handle = opaqueBuf;

  result = CDMi_SUCCESS;
  return result;

error:
  fprintf(stderr,"secure mem malloc failed\n");
  return CDMi_S_FALSE;
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
  fprintf(stderr,"%s\n", m_customData.empty() ? m_customData.c_str() : nullptr);

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
    fprintf(stderr,"playready error2: %s\n", description);
    if (m_piCallback)
        m_piCallback->OnKeyMessage((const uint8_t *) "", 0, "");
  }
  return false;
}

CDMi_RESULT MediaKeySession::Load(void) {
  return CDMi_S_FALSE;
}

void MediaKeySession::SetParameter(const uint8_t * data, const uint32_t length) {
        //fprintf(stderr,"set cbcs parameter\n");
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
      fprintf(stderr,"Drm_Content_SetProperty() failed with %lx", dr);
      goto ErrorExit;
  }

  dr = Drm_Reader_Bind(m_poAppContext,
                        g_rgpdstrRights,
                        DRM_NO_OF(g_rgpdstrRights),
                        _PolicyCallback,
                        nullptr,
                        m_oDecryptContext);
  if (!DRM_SUCCEEDED(dr)) {
      fprintf(stderr,"Drm_Reader_Bind() MODE_HANDLE failed with %lx", dr);
      goto ErrorExit;
  }

  decryptionMode = OEM_TEE_DECRYPTION_MODE_NOT_SECURE;
  dr = Drm_Content_SetProperty(m_poAppContext,
                           DRM_CSP_DECRYPTION_OUTPUT_MODE,
                           (const DRM_BYTE*)&decryptionMode,
                           sizeof decryptionMode);
  if (!DRM_SUCCEEDED(dr)) {
      fprintf(stderr,"Drm_Content_SetProperty() failed with %lx", dr);
      goto ErrorExit;
  }

  dr = Drm_Reader_Bind(m_poAppContext,
                        g_rgpdstrRights,
                        DRM_NO_OF(g_rgpdstrRights),
                        _PolicyCallback,
                        nullptr,
                        m_oDecryptContext2);
  if (!DRM_SUCCEEDED(dr)) {
      fprintf(stderr,"Drm_Reader_Bind() MODE_NOT_SECURE failed with %lx, ignore", dr);
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
    fprintf(stderr,"playready error3: %s\n", description);

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
    SafeCriticalSection systemLock(drmAppContextMutex_);
    assert(sampleInfo->ivLength > 0);
    if (inDataLength == 0) {
        return CDMi_SUCCESS;
    }

    if (!m_oDecryptContext) {
        fprintf(stderr,"Error: no decrypt context (yet?)\n");
        return CDMi_S_FALSE;
    }

    DRM_RESULT err = DRM_SUCCESS;
    DRM_DWORD rgdwMappings[2];
    bool bUseSVP = true;

    if ( (outDataLength == NULL) || (outData == NULL)
        || (sampleInfo->iv == NULL || sampleInfo->ivLength == 0) || (m_eKeyState != KEY_READY) ) {
        fprintf(stderr,"Error: Decrypt - Invalid argument\n");
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
        fprintf(stderr,"Failed to init decrypt\n");
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
      fprintf(stderr,"DYNAMIC_SVP_DECRYPTION parser not set! ");
    }

    DRM_DWORD regionCount[2] = { 0 };
    uint32_t opaque_buffer_size = 0;
    DRM_BYTE *pbEncrypted;
    uint8_t *opaque_buffer = NULL;

    regionCount[0] = 0;
    regionCount[1] = inDataLength;

    if (bUseSVP) {
      Sec_OpaqueBufferHandle*   secbuf_out  = NULL;
      err = SecOpaqueBuffer_Malloc(inDataLength, &secbuf_out);
      if (DRM_FAILED(err)) {
          fprintf(stderr,"Failed to run SecOpaqueBuffer_Malloc\n");
          return CDMi_S_FALSE;
      }

      //OEM_OPTEE_SetHandle(secbuf_out->secmem_handle);
      err = Drm_Reader_DecryptOpaque(
        m_oDecryptContext,
        2, regionCount, iv_vector[0],
        inDataLength, (DRM_BYTE *) inData,
        &opaque_buffer_size,
        &opaque_buffer);
      if (DRM_FAILED(err)) {
          fprintf(stderr,"Failed to run Drm_Reader_DecryptMultipleOpaque1\n");
          return CDMi_S_FALSE;
      }
      if (opaque_buffer) {
          free(opaque_buffer);
          opaque_buffer = NULL;
      }
      // fprintf(stderr,"Drm_Reader_DecryptOpaque video ---- %p\n", secbuf_out);

      uint8_t* ptrData = (uint8_t*)inData + sizeof(uint8_t);
      memcpy((void *)ptrData, secbuf_out, sizeof(Sec_OpaqueBufferHandle));
      // Add a header to the output buffer.
      ((DRM_BYTE*)inData)[0] = 1;   // 0 = inPlace, 1 = handle

      *outDataLength = sizeof(Sec_OpaqueBufferHandle);
      *outData = (uint8_t *)inData;
    } else {
      err = Drm_Reader_DecryptOpaque(
        m_oDecryptContext2,
        2, regionCount, iv_vector[0],
        inDataLength, (DRM_BYTE *) inData,
        &opaque_buffer_size,
        &opaque_buffer);
      if (DRM_FAILED(err)) {
          fprintf(stderr,"Failed to run Drm_Reader_DecryptOpaque\n");
          return CDMi_S_FALSE;
      }
      if (opaque_buffer) {
          memcpy((uint8_t *)inData, opaque_buffer, opaque_buffer_size);
          free(opaque_buffer);
          opaque_buffer = NULL;
      }

      memmove((DRM_BYTE*)inData + sizeof(uint8_t), inData, inDataLength);
      // Add a header to the output buffer.
      ((DRM_BYTE*)inData)[0] = 0;   // 0 = inPlace, 1 = handle

      *outDataLength = inDataLength;
      *outData = (uint8_t *)inData;
    }

    // Call commit during the decryption of the first sample.
    if (!m_fCommit) {
        //err = Drm_Reader_Commit(m_poAppContext, &opencdm_output_levels_callback, &levels_);
        err = Drm_Reader_Commit(m_poAppContext, _PolicyCallback, nullptr); // TODO: pass along user data
        if (DRM_FAILED(err)) {
            fprintf(stderr,"Failed to do Reader Commit\n");
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
