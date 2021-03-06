if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703813" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2016-8714" );
	script_name( "Debian Security Advisory DSA 3813-1 (r-base - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-19 00:00:00 +0100 (Sun, 19 Mar 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3813.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "r-base on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 3.1.1-1+deb8u1.

For the upcoming stable distribution (stretch), this problem has been
fixed in version 3.3.3-1.

For the unstable distribution (sid), this problem has been fixed in
version 3.3.3-1.

We recommend that you upgrade your r-base packages." );
	script_tag( name: "summary", value: "Cory Duplantis discovered a buffer overflow in the R programming
language. A malformed encoding file may lead to the execution of
arbitrary code during PDF generation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "r-base", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base-core", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base-core-dbg", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base-dev", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base-html", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-doc-html", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-doc-info", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-doc-pdf", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-mathlib", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-recommended", ver: "3.1.1-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base-core", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base-core-dbg", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base-dev", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-base-html", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-doc-html", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-doc-info", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-doc-pdf", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-mathlib", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "r-recommended", ver: "3.3.3-1", rls: "DEB9" ) ) != NULL){
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

