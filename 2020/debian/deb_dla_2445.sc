if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892445" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2020-28241" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-26 03:15:00 +0000 (Sat, 26 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 04:00:26 +0000 (Wed, 11 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for libmaxminddb (DLA-2445-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2445-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/973878" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmaxminddb'
  package(s) announced via the DLA-2445-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A heap-based buffer over-read has been found in libmaxminddb, an IP geolocation
database library. This could be exploited when the mmdblookup tool is used to
open a specially crafted database file." );
	script_tag( name: "affected", value: "'libmaxminddb' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.2.0-1+deb9u1.

We recommend that you upgrade your libmaxminddb packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmaxminddb-dev", ver: "1.2.0-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmaxminddb0", ver: "1.2.0-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mmdb-bin", ver: "1.2.0-1+deb9u1", rls: "DEB9" ) )){
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

