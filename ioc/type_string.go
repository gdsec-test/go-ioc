// Code generated by "stringer -type=Type"; DO NOT EDIT.

package ioc

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Unknown-0]
	_ = x[Bitcoin-1]
	_ = x[Ethereum-2]
	_ = x[Monero-3]
	_ = x[MD5-4]
	_ = x[SHA1-5]
	_ = x[SHA256-6]
	_ = x[SHA512-7]
	_ = x[Domain-8]
	_ = x[Email-9]
	_ = x[IPv4-10]
	_ = x[IPv6-11]
	_ = x[URL-12]
	_ = x[File-13]
	_ = x[CVE-14]
	_ = x[CAPEC-15]
	_ = x[CWE-16]
	_ = x[CPE-17]
	_ = x[MitreMatrix-18]
	_ = x[MitreTactic-19]
	_ = x[MitreTechnique-20]
	_ = x[MitreSubtechnique-21]
	_ = x[MitreMitigation-22]
	_ = x[MitreGroup-23]
	_ = x[MitreSoftware-24]
	_ = x[MitreDetection-25]
	_ = x[AWSHostName-26]
	_ = x[GoDaddyHostName-27]
}

const _Type_name = "UnknownBitcoinEthereumMoneroMD5SHA1SHA256SHA512DomainEmailIPv4IPv6URLFileCVECAPECCWECPEMitreMatrixMitreTacticMitreTechniqueMitreSubtechniqueMitreMitigationMitreGroupMitreSoftwareMitreDetectionAWSHostNameGoDaddyHostName"

var _Type_index = [...]uint8{0, 7, 14, 22, 28, 31, 35, 41, 47, 53, 58, 62, 66, 69, 73, 76, 81, 84, 87, 98, 109, 123, 140, 155, 165, 178, 192, 203, 218}

func (i Type) String() string {
	if i < 0 || i >= Type(len(_Type_index)-1) {
		return "Type(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Type_name[_Type_index[i]:_Type_index[i+1]]
}
