if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890964" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2016-9932", "CVE-2017-7995", "CVE-2017-8903", "CVE-2017-8904", "CVE-2017-8905" );
	script_name( "Debian LTS: Security Advisory for xen (DLA-964-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.1.6.lts1-8.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor. The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2016-9932 (XSA-200)

CMPXCHG8B emulation allows local HVM guest OS users to obtain sensitive
information from host stack memory.

CVE-2017-7995

Description
Xen checks access permissions to MMIO ranges only after accessing them,
allowing host PCI device space memory reads.

CVE-2017-8903 (XSA-213)

Xen mishandles page tables after an IRET hypercall which can lead to
arbitrary code execution on the host OS. The vulnerability is only exposed
to 64-bit PV guests.

CVE-2017-8904 (XSA-214)

Xen mishandles the 'contains segment descriptors' property during
GNTTABOP_transfer. This might allow PV guest OS users to execute arbitrary
code on the host OS.

CVE-2017-8905 (XSA-215)

Xen mishandles a failsafe callback which might allow PV guest OS users to
execute arbitrary code on the host OS." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-4.1", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-ocaml", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-ocaml-dev", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-docs-4.1", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-amd64", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-i386", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-i386", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.1", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.1.6.lts1-8", rls: "DEB7" ) )){
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

