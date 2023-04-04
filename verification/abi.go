package verification

const (
	CmdMagic  uint32 = 0x44504543
	RespMagic uint32 = 0x44504552

	CURRENT_PROFILE_VERSION uint32 = 0
)

type CommandCode uint32

const (
	CommandGetProfile        CommandCode = 0x1
	CommandInitializeContext CommandCode = 0x5
	CommandCertifyKey        CommandCode = 0x7
	CommandDestroyContext    CommandCode = 0xf
	CommandTagTCI            CommandCode = 0x1002
	CommandGetTaggedTCI      CommandCode = 0x1003
)

type CommandHdr struct {
	magic   uint32
	cmd     CommandCode
	profile Profile
}

type RespHdr struct {
	Magic   uint32
	Status  Status
	Profile Profile
}

type InitCtxCmd struct {
	flags uint32
}

func NewInitCtxIsDefault() *InitCtxCmd {
	return &InitCtxCmd{flags: 1 << 30}
}

func NewInitCtxIsSimulation() *InitCtxCmd {
	return &InitCtxCmd{flags: 1 << 31}
}

type ContextHandle [16]byte

type DestroyCtxCmd struct {
	handle ContextHandle
	flags  uint32
}

func NewDestroyCtx(handle ContextHandle, destroy_descendants bool) *DestroyCtxCmd {
	flags := uint32(0)
	if destroy_descendants {
		flags |= 1 << 31
	}
	return &DestroyCtxCmd{handle: handle, flags: flags}
}

type InitCtxResp struct {
	Handle ContextHandle
}

type GetProfileResp struct {
	Profile     Profile
	Version     uint32
	MaxTciNodes uint32
	Flags       uint32
}

type CertifyKeyFlags uint32

const (
	CertifyKeyNDDerivation CertifyKeyFlags = 0x800000
)

type CertifyKeyReq[Digest DigestAlgorithm] struct {
	ContextHandle ContextHandle
	Flags         CertifyKeyFlags
	Label         Digest
}

type CertifyKeyResp[CurveParameter Curve, Digest DigestAlgorithm] struct {
	NewContextHandle  ContextHandle
	DerivedPublicKeyX CurveParameter
	DerivedPublicKeyY CurveParameter
	Certificate       []byte
}

type TCITag uint32

type TagTCIReq struct {
	ContextHandle ContextHandle
	Tag           TCITag
}

type TagTCIResp struct {
	NewContextHandle ContextHandle
}

type GetTaggedTCIReq struct {
	Tag TCITag
}

type GetTaggedTCIResp[Digest DigestAlgorithm] struct {
	CumulativeTCI Digest
	CurrentTCI    Digest
}
