if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891977" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-15681" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 19:51:00 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-10-31 03:00:09 +0000 (Thu, 31 Oct 2019)" );
	script_name( "Debian LTS: Security Advisory for libvncserver (DLA-1977-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/10/msg00039.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1977-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/943793" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvncserver'
  package(s) announced via the DLA-1977-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "LibVNC contained a memory leak (CWE-655) in VNC server code, which
allowed an attacker to read stack memory and could be abused for
information disclosure." );
	script_tag( name: "affected", value: "'libvncserver' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.9.9+dfsg2-6.1+deb8u6.

We recommend that you upgrade your libvncserver packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0", ver: "0.9.9+dfsg2-6.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-config", ver: "0.9.9+dfsg2-6.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-dev", ver: "0.9.9+dfsg2-6.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0", ver: "0.9.9+dfsg2-6.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linuxvnc", ver: "0.9.9+dfsg2-6.1+deb8u6", rls: "DEB8" ) )){
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
