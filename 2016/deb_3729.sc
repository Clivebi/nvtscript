if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703729" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-7777", "CVE-2016-9379", "CVE-2016-9380", "CVE-2016-9382", "CVE-2016-9383", "CVE-2016-9385", "CVE-2016-9386" );
	script_name( "Debian Security Advisory DSA 3729-1 (xen - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-07 00:00:00 +0100 (Wed, 07 Dec 2016)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3729.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 4.4.1-9+deb8u8.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been
discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2016-7777 (XSA-190)

Jan Beulich from SUSE discovered that Xen does not properly honor
CR0.TS and CR0.EM for x86 HVM guests, potentially allowing guest
users to read or modify FPU, MMX, or XMM register state information
belonging to arbitrary tasks on the guest by modifying an
instruction while the hypervisor is preparing to emulate it.

CVE-2016-9379,
CVE-2016-9380 (XSA-198)

Daniel Richman and Gabor Szarka of the Cambridge University
Student-Run Computing Facility discovered that pygrub, the boot
loader emulator, fails to quote (or sanity check) its results when
reporting them to its caller. A malicious guest administrator can
take advantage of this flaw to cause an information leak or denial
of service.

CVE-2016-9382 (XSA-192)

Jan Beulich of SUSE discovered that Xen does not properly handle x86
task switches to VM86 mode. A unprivileged guest process can take
advantage of this flaw to crash the guest or, escalate its
privileges to that of the guest operating system.

CVE-2016-9383 (XSA-195)

George Dunlap of Citrix discovered that the Xen x86 64-bit bit test
instruction emulation is broken. A malicious guest can take
advantage of this flaw to modify arbitrary memory, allowing for
arbitrary code execution, denial of service (host crash), or
information leaks.

CVE-2016-9385 (XSA-193)

Andrew Cooper of Citrix discovered that Xen's x86 segment base write
emulation lacks canonical address checks. A malicious guest
administrator can take advantage of this flaw to crash the host,
leading to a denial of service.

CVE-2016-9386 (XSA-191)

Andrew Cooper of Citrix discovered that x86 null segments are not
always treated as unusable. An unprivileged guest user program
may be able to elevate its privilege to that of the guest
operating system." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-4.4:amd64", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-4.4:amd64", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0:amd64", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0:i386", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-amd64", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-arm64", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-armhf", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-arm64", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-armhf", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.4", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.4.1-9+deb8u8", rls: "DEB8" ) ) != NULL){
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

