if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72172" );
	script_cve_id( "CVE-2012-3515", "CVE-2012-4411" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:24:00 -0400 (Sat, 15 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2543-1 (xen-qemu-dm-4.0)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202543-1" );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in xen-qemu-dm-4.0, the Xen
Qemu Device Model virtual machine hardware emulator. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-3515:

The device model for HVM domains does not properly handle VT100
escape sequences when emulating certain devices with a virtual
console backend. An attacker within a guest with access to the
vulnerable virtual console could overwrite memory of the device
model and escalate privileges to that of the device model process.

CVE-2012-4411:

The qemu monitor was enabled by default, allowing administrators of
a guest to access resources of the host, possibly escalate privileges
or access resources belonging to another guest.

For the stable distribution (squeeze), these problems have been fixed in
version 4.0.1-2+squeeze2.

The testing distribution (wheezy), and the unstable distribution (sid),
no longer contain this package." );
	script_tag( name: "solution", value: "We recommend that you upgrade your xen-qemu-dm-4.0 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to xen-qemu-dm-4.0
announced via advisory DSA 2543-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "xen-qemu-dm-4.0", ver: "4.0.1-2+squeeze2", rls: "DEB6" ) ) != NULL){
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

