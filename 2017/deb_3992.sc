if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703992" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_cve_id( "CVE-2017-1000100", "CVE-2017-1000101", "CVE-2017-1000254" );
	script_name( "Debian Security Advisory DSA 3992-1 (curl - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-06 00:00:00 +0200 (Fri, 06 Oct 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3992.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "curl on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 7.38.0-4+deb8u6.

For the stable distribution (stretch), these problems have been fixed in
version 7.52.1-5+deb9u1.

We recommend that you upgrade your curl packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in cURL, an URL transfer
library. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2017-1000100
Even Rouault reported that cURL does not properly handle long file
names when doing an TFTP upload. A malicious HTTP(S) server can take
advantage of this flaw by redirecting a client using the cURL
library to a crafted TFTP URL and trick it to send private memory
contents to a remote server over UDP.

CVE-2017-1000101
Brian Carpenter and Yongji Ouyang reported that cURL contains a flaw
in the globbing function that parses the numerical range, leading to
an out-of-bounds read when parsing a specially crafted URL.

CVE-2017-1000254
Max Dymond reported that cURL contains an out-of-bounds read flaw in
the FTP PWD response parser. A malicious server can take advantage
of this flaw to effectively prevent a client using the cURL library
to work with it, causing a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "curl", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.52.1-5+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "curl", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-dbg", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-gnutls", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl3-nss", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-doc", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-gnutls-dev", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-nss-dev", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcurl4-openssl-dev", ver: "7.38.0-4+deb8u6", rls: "DEB8" ) ) != NULL){
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

