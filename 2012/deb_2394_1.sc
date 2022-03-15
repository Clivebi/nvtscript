if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70712" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-0216", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3905", "CVE-2011-3919" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:29:27 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2394-1 (libxml2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202394-1" );
	script_tag( name: "insight", value: "Many security problems had been fixed in libxml2, a popular library to handle
XML data files.

CVE-2011-3919:
Jüri Aedla discovered a heap-based buffer overflow that allows remote attackers
to cause a denial of service or possibly have unspecified other impact via
unknown vectors.

CVE-2011-0216:
An Off-by-one error have been discoveried that allows remote attackers to
execute arbitrary code or cause a denial of service.

CVE-2011-2821:
A memory corruption (double free) bug has been identified in libxml2's XPath
engine. Through it, it is possible to an attacker allows cause a denial of
service or possibly have unspecified other impact. This vulnerability does not
affect the oldstable distribution (lenny).

CVE-2011-2834:
Yang Dingning discovered a double free vulnerability related to XPath handling.

CVE-2011-3905:
An out-of-bounds read vulnerability had been discovered, which allows remote
attackers to cause a denial of service.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.6.32.dfsg-5+lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 2.7.8.dfsg-2+squeeze2.

For the testing distribution (wheezy), this problem has been fixed in
version 2.7.8.dfsg-7.

For the unstable distribution (sid), this problem has been fixed in
version 2.7.8.dfsg-7." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libxml2 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libxml2
announced via advisory DSA 2394-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.6.32.dfsg-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.6.32.dfsg-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.6.32.dfsg-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.6.32.dfsg-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.6.32.dfsg-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.6.32.dfsg-5+lenny5", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.7.8.dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.7.8.dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.7.8.dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.7.8.dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.7.8.dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.7.8.dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.7.8.dfsg-2+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2", ver: "2.7.8.dfsg-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.7.8.dfsg-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.7.8.dfsg-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.7.8.dfsg-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.7.8.dfsg-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.7.8.dfsg-7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.7.8.dfsg-7", rls: "DEB7" ) ) != NULL){
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

