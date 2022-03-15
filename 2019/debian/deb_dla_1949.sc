if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891949" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19966" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-10-09 02:00:09 +0000 (Wed, 09 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for xen (DLA-1949-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00008.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1949-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen'
  package(s) announced via the DLA-1949-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor, which
could result in denial of service, information leaks or privilege
escalation." );
	script_tag( name: "affected", value: "'xen' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.4.4lts5-0+deb8u1.

We recommend that you upgrade your xen packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-4.4", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-amd64", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.4-armhf", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-armhf", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.4", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.4.4lts5-0+deb8u1", rls: "DEB8" ) )){
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
exit( 0 );

