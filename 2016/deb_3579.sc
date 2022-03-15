if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703579" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-2099" );
	script_name( "Debian Security Advisory DSA 3579-1 (xerces-c - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-16 00:00:00 +0200 (Mon, 16 May 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3579.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "xerces-c on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 3.1.1-5.1+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 3.1.3+debian-2.

For the unstable distribution (sid), this problem has been fixed in
version 3.1.3+debian-2.

We recommend that you upgrade your xerces-c packages." );
	script_tag( name: "summary", value: "Gustavo Grieco discovered an
use-after-free vulnerability in xerces-c, a
validating XML parser library for C++, due to not properly handling
invalid characters in XML input documents in the DTDScanner." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxerces-c-dev", ver: "3.1.3+debian-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-doc", ver: "3.1.3+debian-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-samples", ver: "3.1.3+debian-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c3.1:amd64", ver: "3.1.3+debian-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c3.1:i386", ver: "3.1.3+debian-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-dev", ver: "3.1.1-5.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-doc", ver: "3.1.1-5.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c-samples", ver: "3.1.1-5.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c3.1:amd64", ver: "3.1.1-5.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxerces-c3.1:i386", ver: "3.1.1-5.1+deb8u2", rls: "DEB8" ) ) != NULL){
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

