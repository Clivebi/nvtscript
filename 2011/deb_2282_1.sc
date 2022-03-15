if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70056" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-07 17:37:07 +0200 (Sun, 07 Aug 2011)" );
	script_cve_id( "CVE-2011-2212", "CVE-2011-2527" );
	script_tag( name: "cvss_base", value: "7.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:C/I:C/A:C" );
	script_name( "Debian Security Advisory DSA 2282-1 (qemu-kvm)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202282-1" );
	script_tag( name: "insight", value: "Two vulnerabilities have been discovered in KVM, a solution for full
virtualization on x86 hardware:

CVE-2011-2212

Nelson Elhage discovered a buffer overflow in the virtio subsystem,
which could lead to denial of service or privilege escalation.

CVE-2011-2527

Andrew Griffiths discovered that group privileges were
insufficiently dropped when started with -runas option, resulting
in privilege escalation.

For the stable distribution (squeeze), this problem has been fixed in
version 0.12.5+dfsg-5+squeeze6.

For the unstable distribution (sid), this problem has been fixed in
version 0.14.1+dfsg-3." );
	script_tag( name: "solution", value: "We recommend that you upgrade your qemu-kvm packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to qemu-kvm
announced via advisory DSA 2282-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kvm", ver: "1:0.12.5+dfsg-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "0.12.5+dfsg-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm-dbg", ver: "0.12.5+dfsg-5+squeeze6", rls: "DEB6" ) ) != NULL){
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

