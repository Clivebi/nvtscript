if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703657" );
	script_version( "2021-09-20T12:48:38+0000" );
	script_cve_id( "CVE-2015-8916", "CVE-2015-8917", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8933", "CVE-2015-8934", "CVE-2016-4300", "CVE-2016-4302", "CVE-2016-4809", "CVE-2016-5844" );
	script_name( "Debian Security Advisory DSA 3657-1 (libarchive - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:48:38 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-07 10:08:38 +0530 (Wed, 07 Sep 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3657.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "libarchive on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these
    problems have been fixed in version 3.1.2-11+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 3.2.1-1.

For the unstable distribution (sid), these problems have been fixed in
version 3.2.1-1.

We recommend that you upgrade your libarchive packages." );
	script_tag( name: "summary", value: "Hanno Boeck and Marcin Noga discovered multiple
    vulnerabilities in libarchive. Processing malformed archives may result in denial of
    service or the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.2.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsdtar", ver: "3.2.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-dev:i386", ver: "3.2.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-dev:amd64", ver: "3.2.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-tools:i386", ver: "3.2.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-tools:amd64", ver: "3.2.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.2.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.2.1-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.1.2-11+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsdtar", ver: "3.1.2-11+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-dev:i386", ver: "3.1.2-11+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-dev:amd64", ver: "3.1.2-11+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive13:i386", ver: "3.1.2-11+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive13:amd64", ver: "3.1.2-11+deb8u2", rls: "DEB8" ) ) != NULL){
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

