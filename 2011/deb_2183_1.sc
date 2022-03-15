if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69118" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0530", "CVE-2005-3534" );
	script_name( "Debian Security Advisory DSA 2183-1 (nbd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_tag( name: "insight", value: "It was discovered a regression of a buffer overflow (CVE-2005-3534) in nbd,
the Network Block Device server, that could allow arbitrary code execution
on the NBD server via a large request." );
	script_tag( name: "summary", value: "The remote host is missing an update to nbd
announced via advisory DSA 2183-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
version 1:2.9.11-3lenny1.

The stable distribution (squeeze), the testing distribution (wheezy),
and the unstable distribution (sid) are not affected. This problem was
fixed prior the release of squeeze in version 1:2.9.16-8.

We recommend that you upgrade your nbd packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202183-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "nbd-client", ver: "1:2.9.11-3lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nbd-client-udeb", ver: "1:2.9.11-3lenny1", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nbd-server", ver: "1:2.9.11-3lenny1", rls: "DEB5" ) ) != NULL){
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

