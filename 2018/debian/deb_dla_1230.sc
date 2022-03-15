if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891230" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-17044", "CVE-2017-17045", "CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566" );
	script_name( "Debian LTS: Security Advisory for xen (DLA-1230-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-09 00:00:00 +0100 (Tue, 09 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/01/msg00003.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.1.6.lts1-11.

We recommend that you upgrade your xen packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor, which
could result in denial of service, information leaks, privilege escalation
or the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-4.1", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-ocaml", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-ocaml-dev", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-docs-4.1", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-amd64", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.1-i386", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-i386", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.1", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.1.6.lts1-11", rls: "DEB7" ) )){
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

