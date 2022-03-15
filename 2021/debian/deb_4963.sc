if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704963" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2021-3711", "CVE-2021-3712" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-31 16:37:00 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-25 03:00:14 +0000 (Wed, 25 Aug 2021)" );
	script_name( "Debian: Security Advisory for openssl (DSA-4963-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|11)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4963.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4963-1" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20210824.txt" );
	script_xref( name: "Advisory-ID", value: "DSA-4963-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the DSA-4963-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in OpenSSL, a Secure
Sockets Layer toolkit.

CVE-2021-3711
John Ouyang reported a buffer overflow vulnerability in the SM2
decryption. An attacker able to present SM2 content for
decryption to an application can take advantage of this flaw to
change application behaviour or cause the application to crash
(denial of service).

CVE-2021-3712
Ingo Schwarze reported a buffer overrun flaw when processing ASN.1
strings in the X509_aux_print() function, which can result in denial
of service." );
	script_tag( name: "affected", value: "'openssl' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (buster), these problems have been fixed
in version 1.1.1d-0+deb10u7.

For the stable distribution (bullseye), these problems have been fixed in
version 1.1.1k-1+deb11u1.

We recommend that you upgrade your openssl packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.1.1d-0+deb10u7", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.1.1d-0+deb10u7", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.1d-0+deb10u7", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.1.1d-0+deb10u7", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcrypto1.1-udeb", ver: "1.1.1k-1+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-dev", ver: "1.1.1k-1+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl-doc", ver: "1.1.1k-1+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.1", ver: "1.1.1k-1+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libssl1.1-udeb", ver: "1.1.1k-1+deb11u1", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openssl", ver: "1.1.1k-1+deb11u1", rls: "DEB11" ) )){
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
exit( 0 );

