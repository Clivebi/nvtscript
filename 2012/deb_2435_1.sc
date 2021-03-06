if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71240" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4337", "CVE-2011-4328", "CVE-2012-1175" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:54:49 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2435-1 (gnash)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202435-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been identified in Gnash, the GNU Flash
player.

CVE-2012-1175

Tielei Wang from Georgia Tech Information Security Center discovered a
vulnerability in GNU Gnash which is due to an integer overflow
error and can be exploited to cause a heap-based buffer overflow by
tricking a user into opening a specially crafted SWF file.

CVE-2011-4328

Alexander Kurtz discovered an unsafe management of HTTP cookies. Cookie
files are stored under /tmp and have predictable names, vulnerability
that allows a local attacker to overwrite arbitrary files the users has
write permissions for, and are also world-readable which may cause
information leak.

CVE-2010-4337

Jakub Wilk discovered an unsafe management of temporary files during the
build process. Files are stored under /tmp and have predictable names,
vulnerability that allows a local attacker to overwrite arbitrary files
the users has write permissions for.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.8-5+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.10-5." );
	script_tag( name: "solution", value: "We recommend that you upgrade your gnash packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to gnash
announced via advisory DSA 2435-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "browser-plugin-gnash", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnash", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnash-common", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnash-common-opengl", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnash-cygnal", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnash-dbg", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnash-doc", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnash-opengl", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnash-tools", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "klash", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "klash-opengl", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "konqueror-plugin-gnash", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mozilla-plugin-gnash", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swfdec-gnome", ver: "1:0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "swfdec-mozilla", ver: "0.8.8-5+squeeze1", rls: "DEB6" ) ) != NULL){
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

