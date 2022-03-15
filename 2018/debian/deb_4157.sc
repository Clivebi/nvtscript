if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704157" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2017-3738", "CVE-2018-0739" );
	script_name( "Debian Security Advisory DSA 4157-1 (openssl - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-29 00:00:00 +0200 (Thu, 29 Mar 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 19:30:00 +0000 (Tue, 23 Apr 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4157.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "openssl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1.0.1t-1+deb8u8. The oldstable distribution is not affected
by CVE-2017-3738
.

For the stable distribution (stretch), these problems have been fixed in
version 1.1.0f-3+deb9u2.

We recommend that you upgrade your openssl packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/openssl" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in OpenSSL, a Secure
Sockets Layer toolkit. The Common Vulnerabilities and Exposures project
identifies the following issues:

CVE-2017-3738
David Benjamin of Google reported an overflow bug in the AVX2
Montgomery multiplication procedure used in exponentiation with
1024-bit moduli.

CVE-2018-0739
It was discovered that constructed ASN.1 types with a recursive
definition could exceed the stack, potentially leading to a denial
of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.1.0f-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.1.0f-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.0f-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.1.0f-3+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.0.1t-1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.0.1t-1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.0", ver: "1.0.1t-1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.0.0-dbg", ver: "1.0.1t-1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.0.1t-1+deb8u8", rls: "DEB8" ) )){
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

