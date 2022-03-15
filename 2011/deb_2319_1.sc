if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70408" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-1485" );
	script_name( "Debian Security Advisory DSA 2319-1 (policykit-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202319-1" );
	script_tag( name: "insight", value: "Neel Mehta discovered that a race condition in Policykit, a framework
for managing administrative policies and privileges, allowed local
users to elevate privileges by executing a setuid program from pkexec.

The oldstable distribution (lenny) does not contain the policykit-1
package.

For the stable distribution (squeeze), this problem has been fixed in
version 0.96-4+squeeze1.

For the testing distribution (wheezy) and unstable distribution (sid),
this problem has been fixed in version 0.101-4." );
	script_tag( name: "solution", value: "We recommend that you upgrade your policykit-1 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to policykit-1
announced via advisory DSA 2319-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpolkit-agent-1-0", ver: "0.96-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-agent-1-dev", ver: "0.96-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-backend-1-0", ver: "0.96-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-backend-1-dev", ver: "0.96-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-gobject-1-0", ver: "0.96-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-gobject-1-dev", ver: "0.96-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "policykit-1", ver: "0.96-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "policykit-1-doc", ver: "0.96-4+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gir1.2-polkit-1.0", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-agent-1-0", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-agent-1-dev", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-backend-1-0", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-backend-1-dev", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-gobject-1-0", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpolkit-gobject-1-dev", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "policykit-1", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "policykit-1-doc", ver: "0.102-1", rls: "DEB7" ) ) != NULL){
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

