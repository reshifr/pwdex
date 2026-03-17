#include <Windows.h>
#include <cstdio>
#include <webauthn.h>
#include <vector>
#include <string>

int main(void)
{

	HWND hWnd = GetForegroundWindow();

	WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = {};
	rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
	rpInfo.pwszId = L"pwdex";
	rpInfo.pwszName = L"pwdex";
	rpInfo.pwszIcon = nullptr;

	std::vector<BYTE> userId = {0x01, 0x02, 0x03, 0x04};
	WEBAUTHN_USER_ENTITY_INFORMATION userInfo = {};
	userInfo.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
	userInfo.cbId = 1000;
	userInfo.pbId = userId.data();
	userInfo.pwszName = L"renol@renol.my.id";
	userInfo.pwszIcon = nullptr;
	userInfo.pwszDisplayName = L"Renol P. H.";

	WEBAUTHN_COSE_CREDENTIAL_PARAMETER credentialParams = {};
	credentialParams.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
	credentialParams.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
	credentialParams.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;

	WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyCredParams = {};
	pubKeyCredParams.cCredentialParameters = 1;
	pubKeyCredParams.pCredentialParameters = &credentialParams;

	std::string clientDataJSON = "{\"type\":\"webauthn.create\",\"challenge\":\"Y2hhbGxlbmdl\",\"origin\":\"http://localhost\"}";
	WEBAUTHN_CLIENT_DATA webAuthNClientData = {};
	webAuthNClientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
	webAuthNClientData.cbClientDataJSON = (DWORD)clientDataJSON.size();
	webAuthNClientData.pbClientDataJSON = (PBYTE)clientDataJSON.c_str();
	webAuthNClientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

	WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = {};
	options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
	options.dwTimeoutMilliseconds = 60000;
	options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
	options.bRequireResidentKey = TRUE;
	options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
	options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
	options.bEnablePrf = TRUE;
	options.pCancellationId = nullptr;
	options.pExcludeCredentialList = nullptr;

	// --- Eksekusi & Penampung Hasil ---
	PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr; // Penampung kado

	printf("Memanggil Windows Hello... Siapkan jari/HP!\n");

	HRESULT hr = WebAuthNAuthenticatorMakeCredential(
			hWnd,
			&rpInfo,
			&userInfo,
			&pubKeyCredParams,
			&webAuthNClientData,
			&options,			// Argumen ke-6
			&pAttestation // Argumen ke-7 (Hasilnya di sini)
	);

	if (SUCCEEDED(hr))
	{
		printf("MANTAP BOSQ! Berhasil.\n");
		printf("Credential ID Size: %d\n", pAttestation->cbCredentialId);

		// JANGAN LUPA DIBERSIHIN
		WebAuthNFreeCredentialAttestation(pAttestation);
	}
	else
	{
		printf("GAGAL total! HRESULT: 0x%X\n", hr);
	}

	return 0;
}
