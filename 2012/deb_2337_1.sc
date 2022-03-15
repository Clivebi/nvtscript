if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70551" );
	script_tag( name: "cvss_base", value: "7.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-1166", "CVE-2011-1583", "CVE-2011-1898", "CVE-2011-3262" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:27:52 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2337-1 (xen)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202337-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the Xen virtual machine
hypervisor.

CVE-2011-1166

A 64-bit guest can get one of its vCPU'ss into non-kernel
mode without first providing a valid non-kernel pagetable,
thereby locking up the host system.

CVE-2011-1583, CVE-2011-3262

Local users can cause a denial of service and possibly execute
arbitrary code via a crafted paravirtualised guest kernel image.

CVE-2011-1898

When using PCI passthrough on Intel VT-d chipsets that do not
have interrupt remapping, guest OS can users to gain host OS
privileges by writing to the interrupt injection registers.

The oldstable distribution (lenny) contains a different version of Xen
not affected by these problems.

For the stable distribution (squeeze), this problem has been fixed in
version 4.0.1-4.

For the testing (wheezy) and unstable distribution (sid), this problem
has been fixed in version 4.1.1-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to xen
announced via advisory DSA 2337-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.0.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.0.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-docs-4.0", ver: "4.0.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-amd64", ver: "4.0.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-i386", ver: "4.0.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.0", ver: "4.0.1-4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.0.1-4", rls: "DEB6" ) ) != NULL){
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

