if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70695" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2011-4339" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 03:22:50 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2376-2 (ipmitool)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202376-2" );
	script_tag( name: "insight", value: "It was discovered that OpenIPMI, the Intelligent Platform Management
Interface library and tools, used too wide permissions PID file,
which allows local users to kill arbitrary processes by writing to
this file.

The original announcement didn't contain corrections for the Debian
5.0 lenny distribution. This update adds packages for lenny.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.8.9-2+squeeze1. (Although the version number contains the
string squeeze, this is in fact an update for lenny.)

For the stable distribution (squeeze), this problem has been fixed in
version 1.8.11-2+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 1.8.11-5." );
	script_tag( name: "solution", value: "We recommend that you upgrade your ipmitool packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to ipmitool
announced via advisory DSA 2376-2." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ipmitool", ver: "1.8.9-2+squeeze1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ipmitool", ver: "1.8.11-2+squeeze2", rls: "DEB6" ) ) != NULL){
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

