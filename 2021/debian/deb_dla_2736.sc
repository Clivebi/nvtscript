if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892736" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_cve_id( "CVE-2021-38165" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-24 16:35:00 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-10 03:00:06 +0000 (Tue, 10 Aug 2021)" );
	script_name( "Debian LTS: Security Advisory for lynx (DLA-2736-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/08/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2736-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2736-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/991971" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lynx'
  package(s) announced via the DLA-2736-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a remote authentication credential
leak in the 'lynx' text-based web browser.

The package now correctly handles authentication subcomponents in
URIs (eg. https://user:pass@example.com) to avoid remote attackers
discovering cleartext credentials in SSL connection data." );
	script_tag( name: "affected", value: "'lynx' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
2.8.9dev11-1+deb9u1.

We recommend that you upgrade your lynx packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "lynx", ver: "2.8.9dev11-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lynx-common", ver: "2.8.9dev11-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lynx-cur", ver: "2.8.9dev11-1+deb9u1", rls: "DEB9" ) )){
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

