if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70564" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-4170", "CVE-2010-4171", "CVE-2011-2503" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:31:24 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2348-1 (systemtap)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202348-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in SystemTap, an instrumentation
system for Linux:

CVE-2011-2503

It was discovered that a race condition in staprun could lead to
privilege escalation.

CVE-2010-4170

It was discovered that insufficient validation of environment
variables in staprun could lead to privilege escalation.

CVE-2010-4171

It was discovered that insufficient validation of module unloading
could lead to denial of service.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2-5+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 1.6-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your systemtap packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to systemtap
announced via advisory DSA 2348-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "systemtap", ver: "1.2-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "systemtap-client", ver: "1.2-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "systemtap-common", ver: "1.2-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "systemtap-doc", ver: "1.2-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "systemtap-grapher", ver: "1.2-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "systemtap-runtime", ver: "1.2-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "systemtap-sdt-dev", ver: "1.2-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "systemtap-server", ver: "1.2-5+squeeze1", rls: "DEB6" ) ) != NULL){
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

