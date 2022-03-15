if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71820" );
	script_cve_id( "CVE-2012-3432", "CVE-2012-3433" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:32:13 -0400 (Thu, 30 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2531-1 (xen)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202531-1" );
	script_tag( name: "insight", value: "Several denial-of-service vulnerabilities have been discovered in Xen,
the popular virtualization software. The Common Vulnerabilities and
Exposures project identifies the following issues:

CVE-2012-3432

Guest mode unprivileged code, which has been granted the privilege to
access MMIO regions, may leverage that access to crash the whole guest.
Since this be used to crash a client from within, this vulnerability is
consider with low impact.

CVE-2012-3433

A guest kernel can cause the host to become unresponsive for a period
of time, potentially leading to a DoS. Since an attacker with full
control in the guest can impact on the host, this vulnerability is
consider with high impact.

For the stable distribution (squeeze), this problem has been fixed in
version 4.0.1-5.3.

For the unstable distribution (sid), this problem has been fixed in
version 4.1.3-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to xen
announced via advisory DSA 2531-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.0.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.0.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-docs-4.0", ver: "4.0.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-amd64", ver: "4.0.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-i386", ver: "4.0.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.0", ver: "4.0.1-5.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.0.1-5.3", rls: "DEB6" ) ) != NULL){
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

