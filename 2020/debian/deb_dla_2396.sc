if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892396" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-26117" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-06 01:15:00 +0000 (Fri, 06 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-07 03:00:08 +0000 (Wed, 07 Oct 2020)" );
	script_name( "Debian LTS: Security Advisory for tigervnc (DLA-2396-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/10/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2396-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/971272" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tigervnc'
  package(s) announced via the DLA-2396-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in tigernvc, a Virtual Network Computing
client and server implementation. The viewer implementation mishandles
TLS certificate exceptions, storing the certificates as authorities,
meaning that the owner of a certificate could impersonate any server
after a client had added an exception." );
	script_tag( name: "affected", value: "'tigervnc' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.7.0+dfsg-7+deb9u2.

We recommend that you upgrade your tigervnc packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "tigervnc-common", ver: "1.7.0+dfsg-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tigervnc-scraping-server", ver: "1.7.0+dfsg-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tigervnc-standalone-server", ver: "1.7.0+dfsg-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tigervnc-viewer", ver: "1.7.0+dfsg-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tigervnc-xorg-extension", ver: "1.7.0+dfsg-7+deb9u2", rls: "DEB9" ) )){
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

