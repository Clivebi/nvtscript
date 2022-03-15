if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702719" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1790", "CVE-2013-1788" );
	script_name( "Debian Security Advisory DSA 2719-1 (poppler - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-10 00:00:00 +0200 (Wed, 10 Jul 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2719.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "poppler on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 0.12.4-1.2+squeeze3.

For the stable (wheezy), testing (jessie), and unstable (sid)
distributions, these problems have been fixed in version 0.18.4-6.

We recommend that you upgrade your poppler packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in the poppler PDF rendering
library.

CVE-2013-1788
Multiple invalid memory access issues, which could potentially lead
to arbitrary code execution if the user were tricked into opening a
malformed PDF document.

CVE-2013-1790
An uninitialized memory issue, which could potentially lead to
arbitrary code execution if the user were tricked into opening a
malformed PDF document." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpoppler-dev", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-glib-dev", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-glib4", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-qt-dev", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-qt2", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-qt4-3", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-qt4-dev", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler5", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "poppler-dbg", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.12.4-1.2+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gir1.2-poppler-0.18", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-cpp-dev", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-cpp0", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-dev", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-glib-dev", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-glib8", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-private-dev", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-qt4-3", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler-qt4-dev", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpoppler19", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "poppler-dbg", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.18.4-6", rls: "DEB7" ) ) != NULL){
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

