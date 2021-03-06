if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71501" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-3292" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:21:12 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2523-1 (globus-gridftp-server)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202523-1" );
	script_tag( name: "insight", value: "It was discovered that the GridFTP component from the Globus Toolkit, a
toolkit used for building Grid systems and applications performed
insufficient validation of a name lookup, which could lead to privilege
escalation.

For the stable distribution (squeeze), this problem has been fixed in
version 3.23-1+squeeze1 of the globus-gridftp-server source package
and in version 0.43-1+squeeze1 of the globus-gridftp-server-control
source package

For the testing distribution (wheezy) and the unstable distribution (sid),
this problem has been fixed in version 6.5-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your globus-gridftp-server packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to globus-gridftp-server
announced via advisory DSA 2523-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "globus-gridftp-server-dbg", ver: "3.23-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "globus-gridftp-server-progs", ver: "3.23-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libglobus-gridftp-server-dev", ver: "3.23-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libglobus-gridftp-server0", ver: "3.23-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "globus-gridftp-server-dbg", ver: "6.10-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "globus-gridftp-server-progs", ver: "6.10-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libglobus-gridftp-server-dev", ver: "6.10-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libglobus-gridftp-server6", ver: "6.10-2", rls: "DEB7" ) ) != NULL){
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

