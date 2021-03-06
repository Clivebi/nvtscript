if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72173" );
	script_cve_id( "CVE-2012-3494", "CVE-2012-3496" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:C" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:24:09 -0400 (Sat, 15 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2544-1 (xen)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202544-1" );
	script_tag( name: "insight", value: "Multiple denial of service vulnerabilities have been discovered in xen,
an hypervisor. The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2012-3494:

It was discovered that set_debugreg allows writes to reserved bits
of the DR7 debug control register on amd64 (x86-64) paravirtualised
guests, allowing a guest to crash the host.

CVE-2012-3496:

Matthew Daley discovered that XENMEM_populate_physmap, when called
with the MEMF_populate_on_demand flag set, a BUG (detection routine)
can be triggered if a translating paging mode is not being used,
allowing a guest to crash the host.

For the stable distribution (squeeze), these problems have been fixed in
version 4.0.1-5.4.

For the testing distribution (wheezy), these problems will be fixed
soon.

For the unstable distribution (sid), these problems have been fixed in
version 4.1.3-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to xen
announced via advisory DSA 2544-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.0.1-5.4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.0.1-5.4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-docs-4.0", ver: "4.0.1-5.4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-amd64", ver: "4.0.1-5.4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-i386", ver: "4.0.1-5.4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.0", ver: "4.0.1-5.4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.0.1-5.4", rls: "DEB6" ) ) != NULL){
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

