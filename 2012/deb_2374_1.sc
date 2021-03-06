if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70692" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-4073" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:21:50 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2374-1 (openswan)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202374-1" );
	script_tag( name: "insight", value: "The information security group at ETH Zurich discovered a denial of
service vulnerability in the crypto helper handler of the IKE daemon
pluto.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:2.4.12+dfsg-1.3+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 1:2.6.28+dfsg-5+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 1:2.6.37-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your openswan packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to openswan
announced via advisory DSA 2374-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "linux-patch-openswan", ver: "1:2.4.12+dfsg-1.3+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openswan", ver: "1:2.4.12+dfsg-1.3+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openswan-modules-source", ver: "1:2.4.12+dfsg-1.3+lenny4", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openswan", ver: "1:2.6.28+dfsg-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openswan-dbg", ver: "1:2.6.28+dfsg-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openswan-doc", ver: "1:2.6.28+dfsg-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openswan-modules-dkms", ver: "1:2.6.28+dfsg-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openswan-modules-source", ver: "1:2.6.28+dfsg-5+squeeze1", rls: "DEB6" ) ) != NULL){
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

