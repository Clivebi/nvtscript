if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703633" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-8338", "CVE-2016-4480", "CVE-2016-4962", "CVE-2016-5242", "CVE-2016-6258" );
	script_name( "Debian Security Advisory DSA 3633-1 (xen - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-02 10:55:39 +0530 (Tue, 02 Aug 2016)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3633.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 4.4.1-9+deb8u6.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been
discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2015-8338
Julien Grall discovered that Xen on ARM was susceptible to denial
of service via long running memory operations.

CVE-2016-4480
Jan Beulich discovered that incorrect page table handling could
result in privilege escalation inside a Xen guest instance.

CVE-2016-4962
Wei Liu discovered multiple cases of missing input sanitising in
libxl which could result in denial of service.

CVE-2016-5242
Aaron Cornelius discovered that incorrect resource handling on
ARM systems could result in denial of service.

CVE-2016-6258
Jeremie Boutoille discovered that incorrect pagetable handling in
PV instances could result in guest to host privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxen-4.4:amd64", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-4.4:i386", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0:amd64", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxenstore3.0:i386", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-amd64", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-arm64", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-armhf", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-arm64", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-system-armhf", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-4.4", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.4.1-9+deb8u6", rls: "DEB8" ) ) != NULL){
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

