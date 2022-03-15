if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72537" );
	script_cve_id( "CVE-2012-5671" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-29 10:21:14 -0400 (Mon, 29 Oct 2012)" );
	script_name( "Debian Security Advisory DSA 2566-1 (exim4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202566-1" );
	script_tag( name: "insight", value: "It was discovered that Exim, a mail transport agent, is not properly
handling the decoding of DNS records for DKIM.  Specifically, crafted
records can yield to a heap-based buffer overflow.  An attacker can
exploit this flaw to execute arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in
version 4.72-6+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in
version 4.80-5.1.

For the unstable distribution (sid), this problem has been fixed in
version 4.80-5.1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your exim4 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to exim4
announced via advisory DSA 2566-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "exim4", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.72-6+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.80-5.1", rls: "DEB7" ) ) != NULL){
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

