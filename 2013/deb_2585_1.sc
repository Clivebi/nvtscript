if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702585" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-5468" );
	script_name( "Debian Security Advisory DSA 2585-1 (bogofilter - buffer overflow)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2585.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "bogofilter on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.2.2-2+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 1.2.2+dfsg1-2.

We recommend that you upgrade your bogofilter packages." );
	script_tag( name: "summary", value: "A heap-based buffer overflow was discovered in bogofilter, a software
package for classifying mail messages as spam or non-spam. Crafted
mail messages with invalid base64 data could lead to heap corruption
and, potentially, arbitrary code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bogofilter", ver: "1.2.2-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter-bdb", ver: "1.2.2-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter-common", ver: "1.2.2-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter-sqlite", ver: "1.2.2-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter-tokyocabinet", ver: "1.2.2-2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter", ver: "1.2.2+dfsg1-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter-bdb", ver: "1.2.2+dfsg1-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter-common", ver: "1.2.2+dfsg1-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter-sqlite", ver: "1.2.2+dfsg1-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bogofilter-tokyocabinet", ver: "1.2.2+dfsg1-2", rls: "DEB7" ) ) != NULL){
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

