if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703889" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_cve_id( "CVE-2017-1000376" );
	script_name( "Debian Security Advisory DSA 3889-1 (libffi - security update)" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-19 00:00:00 +0200 (Mon, 19 Jun 2017)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-15 20:15:00 +0000 (Wed, 15 Jan 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3889.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|10|8)" );
	script_tag( name: "affected", value: "libffi on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 3.1-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 3.2.1-4.

For the testing distribution (buster), this problem has been fixed
in version 3.2.1-4.

For the unstable distribution (sid), this problem has been fixed in
version 3.2.1-4.

We recommend that you upgrade your libffi packages." );
	script_tag( name: "summary", value: "libffi, a library used to call code written in one language from code written
in a different language, was enforcing an executable stack on the i386
architecture. While this might not be considered a vulnerability by itself,
this could be leveraged when exploiting other vulnerabilities, like for example
the stack clash class of vulnerabilities discovered by Qualys Research Labs." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libffi-dev", ver: "3.2.1-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi6", ver: "3.2.1-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi6-dbg", ver: "3.2.1-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi6-udeb", ver: "3.2.1-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi-dev", ver: "3.2.1-4", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi6", ver: "3.2.1-4", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi6-dbg", ver: "3.2.1-4", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi6-udeb", ver: "3.2.1-4", rls: "DEB10" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi-dev", ver: "3.1-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi6", ver: "3.1-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libffi6-dbg", ver: "3.1-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

