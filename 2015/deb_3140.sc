if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703140" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9030" );
	script_name( "Debian Security Advisory DSA 3140-1 (xen - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-01-27 00:00:00 +0100 (Tue, 27 Jan 2015)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3140.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 4.1.4-3+deb7u4.

For the upcoming stable distribution (jessie), these problems have been
fixed in version 4.4.1-4.

For the unstable distribution (sid), these problems have been fixed in
version 4.4.1-4.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "Multiple security issues have
been discovered in the Xen virtualisation solution which may result in
denial of service, information disclosure or privilege escalation.

CVE-2014-8594
Roger Pau Monne and Jan Beulich discovered that incomplete
restrictions on MMU update hypercalls may result in privilege
escalation.

CVE-2014-8595
Jan Beulich discovered that missing privilege level checks in the
x86 emulation of far branches may result in privilege escalation.

CVE-2014-8866
Jan Beulich discovered that an error in compatibility mode hypercall
argument translation may result in denial of service.

CVE-2014-8867Jan Beulich discovered that an insufficient restriction in
acceleration support for the REP MOVS
instruction may result in
denial of service.

CVE-2014-9030
Andrew Cooper discovered a page reference leak in MMU_MACHPHYS_UPDATE
handling, resulting in denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-4.1", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-ocaml", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-ocaml-dev", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-docs-4.1", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-amd64", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-i386", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-i386", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.1", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.1.4-3+deb7u4", rls: "DEB7" ) ) != NULL){
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

