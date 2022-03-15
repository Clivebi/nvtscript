if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702662" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1917", "CVE-2013-1919" );
	script_name( "Debian Security Advisory DSA 2662-1 (xen - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-04-18 00:00:00 +0200 (Thu, 18 Apr 2013)" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2662.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), these problems have been fixed in
version 4.0.1-5.9.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2013-1917
The SYSENTER instruction can be used by PV guests to accelerate
system call processing. This instruction, however, leaves the EFLAGS
register mostly unmodified. This can be used by malicious or buggy
user space to cause the entire host to crash.

CVE-2013-1919
Various IRQ related access control operations may not have the
intended effect, potentially permitting a stub domain to grant its
client domain access to an IRQ it doesn't have access to itself.
This can be used by malicious or buggy stub domains kernels to mount
a denial of service attack possibly affecting the whole system." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.0.1-5.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.0.1-5.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-docs-4.0", ver: "4.0.1-5.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-amd64", ver: "4.0.1-5.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-i386", ver: "4.0.1-5.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.0", ver: "4.0.1-5.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.0.1-5.9", rls: "DEB6" ) ) != NULL){
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

