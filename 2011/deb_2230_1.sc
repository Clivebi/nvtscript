if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69572" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_cve_id( "CVE-2011-0011", "CVE-2011-1750" );
	script_tag( name: "cvss_base", value: "7.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:S/C:C/I:C/A:C" );
	script_name( "Debian Security Advisory DSA 2230-1 (qemu-kvm)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202230-1" );
	script_tag( name: "insight", value: "Two vulnerabilities have been discovered in KVM, a solution for full
virtualization on x86 hardware:

CVE-2011-0011

Setting the VNC password to an empty string silently disabled
all authentication.

CVE-2011-1750

The virtio-blk driver performed insufficient validation of
read/write I/O from the guest instance, which could lead to
denial of service or privilege escalation.


The oldstable distribution (lenny) is not affected by this problem.

For the stable distribution (squeeze), this problem has been fixed in
version 0.12.5+dfsg-5+squeeze1.

The unstable distribution (sid) will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your qemu-kvm packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to qemu-kvm
announced via advisory DSA 2230-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "kvm", ver: "0.12.5+dfsg-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm", ver: "0.12.5+dfsg-5+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "qemu-kvm-dbg", ver: "0.12.5+dfsg-5+squeeze1", rls: "DEB6" ) ) != NULL){
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

