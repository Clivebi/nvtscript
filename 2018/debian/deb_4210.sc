if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704210" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2018-3639" );
	script_name( "Debian Security Advisory DSA 4210-1 (xen - security update)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-25 00:00:00 +0200 (Fri, 25 May 2018)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:51:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4210.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7.

We recommend that you upgrade your xen packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/xen" );
	script_tag( name: "summary", value: "This update provides mitigations for the Spectre v4 variant in x86-based
micro processors. On Intel CPUs this requires updated microcode which
is currently not released publicly (but your hardware vendor may have
issued an update). For servers with AMD CPUs no microcode update is
needed, please
for further information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_xref( name: "URL", value: "https://xenbits.xen.org/xsa/advisory-263.html" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-4.8", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.8-amd64", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.8-arm64", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.8-armhf", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-arm64", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-armhf", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.8", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u7", rls: "DEB9" ) )){
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

