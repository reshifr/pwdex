//go:build linux
// +build linux

package cryptodev

import (
	"encoding/hex"
	"errors"
	"log"

	tpm2 "github.com/google/go-tpm/tpm2"
	tpm2transport "github.com/google/go-tpm/tpm2/transport"
	linuxtpm2 "github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const (
	LinuxTPM2Path             = "/dev/tpmrm0"
	LinuxTPM2PCR              = 7
	LinuxTPM2PersistentHandle = 0x81777777
)

var (
	// LinuxTPM2Template = tpm2.TPMTPublic{
	// 	Type:    tpm2.TPMAlgRSA,
	// 	NameAlg: tpm2.TPMAlgSHA256,
	// 	ObjectAttributes: tpm2.TPMAObject{
	// 		FixedTPM:            true,
	// 		FixedParent:         true,
	// 		SensitiveDataOrigin: true,
	// 		AdminWithPolicy:     true,
	// 		Decrypt:             true,
	// 		// FixedTPM:             true,
	// 		// STClear:              false,
	// 		// FixedParent:          true,
	// 		// SensitiveDataOrigin:  true,
	// 		// UserWithAuth:         true,
	// 		// AdminWithPolicy:      true,
	// 		// FirmwareLimited:      true,
	// 		// NoDA:                 true,
	// 		// EncryptedDuplication: false,
	// 		// Restricted:           false,
	// 		// Decrypt:              true,
	// 		// SignEncrypt:          false,
	// 		// X509Sign:             false,
	// 	},
	// 	Parameters: tpm2.NewTPMUPublicParms(
	// 		tpm2.TPMAlgRSA,
	// 		&tpm2.TPMSRSAParms{
	// 			Symmetric: tpm2.TPMTSymDefObject{
	// 				Algorithm: tpm2.TPMAlgNull,
	// 			},
	// 			Scheme: tpm2.TPMTRSAScheme{
	// 				Scheme: tpm2.TPMAlgOAEP,
	// 				Details: tpm2.NewTPMUAsymScheme(
	// 					tpm2.TPMAlgOAEP,
	// 					&tpm2.TPMSEncSchemeOAEP{
	// 						HashAlg: tpm2.TPMAlgSHA384,
	// 					},
	// 				),
	// 			},
	// 			KeyBits: 3072,
	// 		},
	// 	),
	// 	Unique: tpm2.NewTPMUPublicID(
	// 		tpm2.TPMAlgRSA,
	// 		&tpm2.TPM2BPublicKeyRSA{
	// 			Buffer: make([]byte, 384),
	// 		},
	// 	),
	// }
	LinuxTPM2PCRSelection = tpm2.TPMSPCRSelection{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(LinuxTPM2PCR),
	}
)

type LinuxTPM2 struct {
	rwc tpm2transport.TPMCloser
}

func LinuxTPM2SRKTemplate(rwc tpm2transport.TPMCloser) (tpm2.TPMTPublic, error) {
	pcrReadCmd := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{LinuxTPM2PCRSelection},
		},
	}
	pcrReadRsp, err := pcrReadCmd.Execute(rwc)
	if err != nil {
		log.Fatalf("tpm2.ReadPublic: %v", err)
	}

	sess, cleanup, err := tpm2.PolicySession(rwc, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		log.Fatalf("tpm2.PolicySession: %v", err)
	}
	defer cleanup()

	_, err = tpm2.PolicyPCR(rwc, sess.Handle(), pcrRead.PCRValues.Digests[0], pcrSel)
	if err != nil {
		log.Fatalf("Gagal PolicyPCR: %v", err)
	}

	policyGetDigestCmd := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	policyGetDigestRsp, err := policyGetDigestCmd.Execute(rwc)
	if err != nil {
		log.Fatalf("tpm2.PolicyGetDigest: %v", err)
	}

	pcrRead, err := tpm2.PCRRead(tpm, pcrSel)
	if err != nil {
		log.Fatalf("Gagal baca PCR: %v", err)
	}

	// 5. Jalankan PolicyPCR
	// Ini yang kamu maksud dengan PolicySession: mengikat session ke PCR
	_, err = tpm2.PolicyPCR(tpm, sess.SessionHandle, pcrRead.PCRValues.Digests[0], pcrSel)
	if err != nil {
		log.Fatalf("Gagal PolicyPCR: %v", err)
	}

	// 6. Ambil Policy Digest final
	pgd, err := tpm2.PolicyGetDigest(tpm, sess.SessionHandle)
	if err != nil {
		log.Fatalf("Gagal ambil digest: %v", err)
	}

	// var expectedVal []byte
	// for _, digest := range pcrReadRsp.PCRValues.Digests {
	// 	expectedVal = append(expectedVal, digest.Buffer...)
	// }

	log.Fatalf("tpm2.ReadPublic: %v", hex.EncodeToString(policyGetDigestRsp.PolicyDigest.Buffer))

	// session := tpm2.PolicySession(rwc, tpm2.TPMAlgSHA256)

	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			AdminWithPolicy:     true,
			Decrypt:             true,
		},
		AuthPolicy: pcrReadRsp.PCRValues.Digests[0],
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgNull,
				},
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgOAEP,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgOAEP,
						&tpm2.TPMSEncSchemeOAEP{
							HashAlg: tpm2.TPMAlgSHA384,
						},
					),
				},
				KeyBits: 3072,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 384),
			},
		),
	}, nil
}

func NewLinuxTPM2() {
	rwc, err := linuxtpm2.Open(LinuxTPM2Path)
	if err != nil {
		log.Fatalf("linuxtpm2.Open: %v", err)
	}
	defer rwc.Close()
	handle := tpm2.TPMHandle(LinuxTPM2PersistentHandle)

	readPublicCmd := tpm2.ReadPublic{ObjectHandle: handle}
	readPublicRsp, err := readPublicCmd.Execute(rwc)
	if err != nil && errors.Is(err, tpm2.TPMRC(395)) {
		// pcrReadCmd := tpm2.PCRRead{
		// 	PCRSelectionIn: tpm2.TPMLPCRSelection{
		// 		PCRSelections: []tpm2.TPMSPCRSelection{LinuxTPM2PCRSelection},
		// 	},
		// }
		// pcrReadRsp, err := pcrReadCmd.Execute(rwc)
		// if err != nil {
		// 	log.Fatalf("tpm2.ReadPublic: %v", err)
		// }

		// log.Println(pcrReadRsp.PCRValues.Digests[0].Buffer)

		srkTemplate, err := LinuxTPM2SRKTemplate(rwc)
		if err != nil {
			log.Fatalf("cryptodev.LinuxTPM2SRKTemplate: %v", err)
		}
		createPrimaryCmd := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(srkTemplate),
			CreationPCR: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{LinuxTPM2PCRSelection},
			},
		}
		createPrimaryRsp, err := createPrimaryCmd.Execute(rwc)
		if err != nil {
			log.Fatalf("tpm2.CreatePrimary: %v", err)
		}
		evictControlCmd := tpm2.EvictControl{
			Auth: tpm2.TPMRHOwner,
			ObjectHandle: &tpm2.NamedHandle{
				Handle: createPrimaryRsp.ObjectHandle,
				Name:   createPrimaryRsp.Name,
			},
			PersistentHandle: LinuxTPM2PersistentHandle,
		}
		evictControlRsp, err := evictControlCmd.Execute(rwc)
		if err != nil {
			log.Fatalf("tpm2.EvictControl: %v", err)
		}

		log.Println(evictControlRsp)
	} else if err != nil {
		log.Fatalf("tpm2.ReadPublic: %v", err)
	} else {
		log.Println(readPublicRsp)
	}

}
