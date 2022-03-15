if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70723" );
	script_tag( name: "cvss_base", value: "7.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-0029" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-12 06:39:51 -0500 (Sun, 12 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2404-1 (xen-qemu-dm-4.0)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202404-1" );
	script_tag( name: "insight", value: "Nicolae Mogoraenu discovered a heap overflow in the emulated e1000e
network interface card of QEMU, which is used in the xen-qemu-dm-4.0
packages.  This vulnerability might enable to malicious guest systems
to crash the host system or escalate their privileges.

The old stable distribution (lenny) does not contain the
xen-qemu-dm-4.0 package.

For the stable distribution (squeeze), this problem has been fixed in
version 4.0.1-2+squeeze1.

The testing distribution (wheezy) and the unstable distribution (sid)
will be fixed soon." );
	script_tag( name: "summary", value: "The remote host is missing an update to xen-qemu-dm-4.0
announced via advisory DSA 2404-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "xen-qemu-dm-4.0", ver: "4.0.1-2+squeeze1", rls: "DEB6" ) ) != NULL){
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

