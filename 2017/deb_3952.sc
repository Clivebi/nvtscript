if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703952" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_cve_id( "CVE-2017-0663", "CVE-2017-7375", "CVE-2017-7376", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050" );
	script_name( "Debian Security Advisory DSA 3952-1 (libxml2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-23 00:00:00 +0200 (Wed, 23 Aug 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-17 15:15:00 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3952.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "libxml2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 2.9.1+dfsg1-5+deb8u5.

For the stable distribution (stretch), these problems have been fixed in
version 2.9.4+dfsg1-2.2+deb9u1.

For the unstable distribution (sid), these problems have been fixed in
version 2.9.4+dfsg1-3.1.

We recommend that you upgrade your libxml2 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in libxml2, a library providing
support to read, modify and write XML and HTML files. A remote attacker
could provide a specially crafted XML or HTML file that, when processed
by an application using libxml2, would cause a denial-of-service against
the application, information leaks, or potentially, the execution of
arbitrary code with the privileges of the user running the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.9.1+dfsg1-5+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.9.1+dfsg1-5+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.9.1+dfsg1-5+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.9.1+dfsg1-5+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.9.1+dfsg1-5+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils-dbg", ver: "2.9.1+dfsg1-5+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.9.1+dfsg1-5+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.9.1+dfsg1-5+deb8u5", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils-dbg", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-libxml2", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-libxml2-dbg", ver: "2.9.4+dfsg1-2.2+deb9u1", rls: "DEB9" ) ) != NULL){
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

