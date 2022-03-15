if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702710" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-2156", "CVE-2013-2154", "CVE-2013-2153", "CVE-2013-2155" );
	script_name( "Debian Security Advisory DSA 2710-1 (xml-security-c - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-06-18 00:00:00 +0200 (Tue, 18 Jun 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2710.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "xml-security-c on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.5.1-3+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in
version 1.6.1-5+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.6.1-6.

We recommend that you upgrade your xml-security-c packages." );
	script_tag( name: "summary", value: "James Forshaw from Context Information Security discovered several
vulnerabilities in xml-security-c, an implementation of the XML Digital
Security specification. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2013-2153
The implementation of XML digital signatures in the Santuario-C++
library is vulnerable to a spoofing issue allowing an attacker to
reuse existing signatures with arbitrary content.

CVE-2013-2154
A stack overflow, possibly leading to arbitrary code execution,
exists in the processing of malformed XPointer expressions in the
XML Signature Reference processing code.

CVE-2013-2155
A bug in the processing of the output length of an HMAC-based XML
Signature would cause a denial of service when processing specially
chosen input.

CVE-2013-2156
A heap overflow exists in the processing of the PrefixList attribute
optionally used in conjunction with Exclusive Canonicalization,
potentially allowing arbitrary code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml-security-c-dev", ver: "1.5.1-3+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c15", ver: "1.5.1-3+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c-dev", ver: "1.6.1-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml-security-c16", ver: "1.6.1-5+deb7u1", rls: "DEB7" ) ) != NULL){
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

