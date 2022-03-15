if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703565" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-5726", "CVE-2015-5727", "CVE-2015-7827", "CVE-2016-2194", "CVE-2016-2195", "CVE-2016-2849" );
	script_name( "Debian Security Advisory DSA 3565-1 (botan1.10 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-02 00:00:00 +0200 (Mon, 02 May 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3565.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "botan1.10 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 1.10.8-2+deb8u1.

We recommend that you upgrade your botan1.10 packages." );
	script_tag( name: "summary", value: "Several security vulnerabilities were
found in botan1.10, a C++ library which provides support for many common
cryptographic operations, including encryption, authentication, X.509v3 certificates
and CRLs.

CVE-2015-5726
The BER decoder would crash due to reading from offset 0 of an
empty vector if it encountered a BIT STRING which did not contain
any data at all. This can be used to easily crash applications
reading untrusted ASN.1 data, but does not seem exploitable for
code execution.

CVE-2015-5727
The BER decoder would allocate a fairly arbitrary amount of memory
in a length field, even if there was no chance the read request
would succeed. This might cause the process to run out of memory or
invoke the OOM killer.

CVE-2015-7827
Use constant time PKCS #1 unpadding to avoid possible side channel
attack against RSA decryption

CVE-2016-2194
Infinite loop in modular square root algorithm.
The ressol function implementing the Tonelli-Shanks algorithm for
finding square roots could be sent into a nearly infinite loop due
to a misplaced conditional check. This could occur if a composite
modulus is provided, as this algorithm is only defined for primes.
This function is exposed to attacker controlled input via the
OS2ECP function during ECC point decompression.

CVE-2016-2195
Fix Heap overflow on invalid ECC point.

CVE-2016-2849
Use constant time modular inverse algorithm to avoid possible
side channel attack against ECDSA." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "botan1.10-dbg", ver: "1.10.8-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbotan-1.10-0", ver: "1.10.8-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libbotan1.10-dev", ver: "1.10.8-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

