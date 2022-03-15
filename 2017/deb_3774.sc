if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703774" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_cve_id( "CVE-2016-10165" );
	script_name( "Debian Security Advisory DSA 3774-1 (lcms2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-29 00:00:00 +0100 (Sun, 29 Jan 2017)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3774.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "lcms2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 2.6-3+deb8u1.

For the testing distribution (stretch) and the unstable distribution
(sid), this problem has been fixed in version 2.8-4.

We recommend that you upgrade your lcms2 packages." );
	script_tag( name: "summary", value: "Ibrahim M. El-Sayed discovered an
out-of-bounds heap read vulnerability in the function Type_MLU_Read in lcms2,
the Little CMS 2 color management library, which can be triggered by an image
with a specially crafted ICC profile and leading to a heap memory leak or
denial-of-service for applications using the lcms2 library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "liblcms2-2:amd64", ver: "2.6-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-2:i386", ver: "2.6-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-dbg:amd64", ver: "2.6-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-dbg:i386", ver: "2.6-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-dev:amd64", ver: "2.6-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-dev:i386", ver: "2.6-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-utils", ver: "2.6-3+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-2:amd64", ver: "2.8-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-2:i386", ver: "2.8-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-dev:amd64", ver: "2.8-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-dev:i386", ver: "2.8-4", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblcms2-utils", ver: "2.8-4", rls: "DEB9" ) ) != NULL){
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

