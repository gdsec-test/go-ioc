// Code generated by "stringer -type=Type"; DO NOT EDIT.

package ioc

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Unknown-0]
	_ = x[Bitcoin-1]
	_ = x[MD5-2]
	_ = x[SHA1-3]
	_ = x[SHA256-4]
	_ = x[SHA512-5]
	_ = x[Domain-6]
	_ = x[Email-7]
	_ = x[IPv4-8]
	_ = x[IPv6-9]
	_ = x[URL-10]
	_ = x[File-11]
	_ = x[CVE-12]
	_ = x[CAPEC-13]
	_ = x[CWE-14]
	_ = x[CPE-15]
	_ = x[MitreMatrix-16]
	_ = x[MitreTactic-17]
	_ = x[MitreTechnique-18]
	_ = x[MitreSubtechnique-19]
	_ = x[MitreMitigation-20]
	_ = x[MitreGroup-21]
	_ = x[MitreSoftware-22]
	_ = x[MitreDetection-23]
	_ = x[AWSHostName-24]
	_ = x[GoDaddyHostName-25]
	_ = x[FileRef-26]
	_ = x[FileBase64-27]
}

const _Type_name = "UnknownBitcoinMD5SHA1SHA256SHA512DomainEmailIPv4IPv6URLFileCVECAPECCWECPEMitreMatrixMitreTacticMitreTechniqueMitreSubtechniqueMitreMitigationMitreGroupMitreSoftwareMitreDetectionAWSHostNameGoDaddyHostNameFileRefFileBase64"

var _Type_index = [...]uint8{0, 7, 14, 17, 21, 27, 33, 39, 44, 48, 52, 55, 59, 62, 67, 70, 73, 84, 95, 109, 126, 141, 151, 164, 178, 189, 204, 211, 221}

func (i Type) String() string {
	if i < 0 || i >= Type(len(_Type_index)-1) {
		return "Type(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Type_name[_Type_index[i]:_Type_index[i+1]]
}
