if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70557" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:29:15 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2342-1 (iceape)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202342-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been found in the Iceape internet suite, an
unbranded version of Seamonkey:

CVE-2011-3647

moz_bug_r_a4 discovered a privilege escalation vulnerability in
addon handling.

CVE-2011-3648

Yosuke Hasegawa discovered that incorrect handling of Shift-JIS
encodings could lead to cross-site scripting.

CVE-2011-3650

Marc Schoenefeld discovered that profiling the Javascript code
could lead to memory corruption.

The oldstable distribution (lenny) is not affected. The iceape package only
provides the XPCOM code.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-9.

For the unstable distribution (sid), this problem has been fixed in
version 2.0.14-9." );
	script_tag( name: "solution", value: "We recommend that you upgrade your iceape packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to iceape
announced via advisory DSA 2342-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceape", ver: "2.0.11-10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-browser", ver: "2.0.11-10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-chatzilla", ver: "2.0.11-10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dbg", ver: "2.0.11-10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dev", ver: "2.0.11-10", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-mailnews", ver: "2.0.11-10", rls: "DEB6" ) ) != NULL){
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

