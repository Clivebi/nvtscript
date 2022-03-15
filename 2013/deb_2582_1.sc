if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702582" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-5513", "CVE-2012-4538", "CVE-2012-4535", "CVE-2011-3131", "CVE-2012-5515", "CVE-2012-4539", "CVE-2012-5514", "CVE-2012-5510", "CVE-2012-4537" );
	script_name( "Debian Security Advisory DSA 2582-1 (xen - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2582.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), these problems have been fixed in
version 4.0.1-5.5.

For the testing distribution (wheezy), these problems have been fixed in
version 4.1.3-6.

For the unstable distribution (sid), these problems have been fixed in
version 4.1.3-6.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "Multiple denial of service vulnerabilities have been discovered
in the Xen Hypervisor. One of the issue
(CVE-2012-5513)
could even lead to privilege escalation from guest to host.

Some of the recently published Xen Security Advisories
(XSA 25 and 28)
are not fixed by this update and should be fixed in a future release.

CVE-2011-3131 (XSA 5):
DoS using I/OMMU faults from PCI-passthrough guest
A VM that controls a PCI[E] device directly can cause it to issue DMA
requests to invalid addresses. Although these requests are denied by the
I/OMMU, the hypervisor needs to handle the interrupt and clear the error from
the I/OMMU, and this can be used to live-lock a CPU and potentially hang the
host.

Description truncated. Please see the references for more information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.0.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.0.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-docs-4.0", ver: "4.0.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-amd64", ver: "4.0.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.0-i386", ver: "4.0.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.0", ver: "4.0.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.0.1-5.5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-4.1", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-ocaml", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-ocaml-dev", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-docs-4.1", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-amd64", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-i386", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-i386", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.1", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.1.3-6", rls: "DEB7" ) ) != NULL){
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

