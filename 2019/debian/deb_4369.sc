if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704369" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2017-15595", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-19967" );
	script_name( "Debian Security Advisory DSA 4369-1 (xen - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-14 00:00:00 +0100 (Mon, 14 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 10:29:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4369.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 4.8.5+shim4.10.2+xsa282-1+deb9u11.

We recommend that you upgrade your xen packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/xen" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2018-19961 / CVE-2018-19962

Paul Durrant discovered that incorrect TLB handling could result in
denial of service, privilege escalation or information leaks.

CVE-2018-19965

Matthew Daley discovered that incorrect handling of the INVPCID
instruction could result in denial of service by PV guests.

CVE-2018-19966

It was discovered that a regression in the fix to address CVE-2017-15595 could result in denial of service, privilege
escalation or information leaks by a PV guest.

CVE-2018-19967

It was discovered that an error in some Intel CPUs could result in
denial of service by a guest instance." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-4.8", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.8-amd64", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.8-arm64", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.8-armhf", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-arm64", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-armhf", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.8", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.8.5+shim4.10.2+xsa282-1+deb9u11", rls: "DEB9" ) )){
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

