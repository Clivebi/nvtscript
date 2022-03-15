if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891132" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-10912", "CVE-2017-10913", "CVE-2017-10914", "CVE-2017-10915", "CVE-2017-10918", "CVE-2017-10920", "CVE-2017-10921", "CVE-2017-10922", "CVE-2017-12135", "CVE-2017-12137", "CVE-2017-12855", "CVE-2017-14316", "CVE-2017-14317", "CVE-2017-14318", "CVE-2017-14319" );
	script_name( "Debian LTS: Security Advisory for xen (DLA-1132-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.1.6.lts1-9.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2017-10912

Jann Horn discovered that incorrectly handling of page transfers might
result in privilege escalation.

CVE-2017-10913 / CVE-2017-10914

Jann Horn discovered that race conditions in grant handling might
result in information leaks or privilege escalation.

CVE-2017-10915

Andrew Cooper discovered that incorrect reference counting with
shadow paging might result in privilege escalation.

CVE-2017-10918

Julien Grall discovered that incorrect error handling in
physical-to-machine memory mappings may result in privilege
escalation, denial of service or an information leak.

CVE-2017-10920 / CVE-2017-10921 / CVE-2017-10922

Jan Beulich discovered multiple places where reference
counting on grant table operations was incorrect, resulting
in potential privilege escalation

CVE-2017-12135

Jan Beulich found multiple problems in the handling of
transitive grants which could result in denial of service
and potentially privilege escalation.

CVE-2017-12137

Andrew Cooper discovered that incorrect validation of
grants may result in privilege escalation.

CVE-2017-12855

Jan Beulich discovered that incorrect grant status handling, thus
incorrectly informing the guest that the grant is no longer in use.

CVE-2017-14316

Matthew Daley discovered that the NUMA node parameter wasn't
verified which which may result in privilege escalation.

CVE-2017-14317

Eric Chanudet discovered that a race conditions in cxenstored might
result in information leaks or privilege escalation.

CVE-2017-14318

Matthew Daley discovered that incorrect validation of
grants may result in a denial of service.

CVE-2017-14319

Andrew Cooper discovered that insufficient grant unmapping
checks may result in denial of service and privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-4.1", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-ocaml", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-ocaml-dev", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-docs-4.1", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-amd64", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-i386", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-i386", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.1", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.1.6.lts1-9", rls: "DEB7" ) )){
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

