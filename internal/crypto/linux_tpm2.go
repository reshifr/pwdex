//go:build linux

package crypto

import (
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
	LinuxTPM2NonceSize        = 32
)

var (
	LinuxTPM2PCRSelection = tpm2.TPMSPCRSelection{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(LinuxTPM2PCR),
	}
)

type LinuxTPM2 struct {
	rwc tpm2transport.TPMCloser
}

func LinuxTPM2SRKTemplate(rwc tpm2transport.TPMCloser) (tpm2.TPMTPublic, error) {
	sess, cleanup, err := tpm2.PolicySession(
		rwc,
		tpm2.TPMAlgSHA256,
		LinuxTPM2NonceSize,
		tpm2.Trial(),
	)
	if err != nil {
		log.Fatalf("tpm2.PolicySession: %v", err)
	}
	defer cleanup()

	policyPCRCmd := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{LinuxTPM2PCRSelection},
		},
	}
	_, err = policyPCRCmd.Execute(rwc)
	if err != nil {
		log.Fatalf("tpm2.PolicyPCR: %v", err)
	}

	policyGetDigestCmd := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}
	policyGetDigestRsp, err := policyGetDigestCmd.Execute(rwc)
	if err != nil {
		log.Fatalf("tpm2.PolicyGetDigest: %v", err)
	}

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
		AuthPolicy: policyGetDigestRsp.PolicyDigest,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
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
