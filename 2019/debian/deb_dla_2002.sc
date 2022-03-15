if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892002" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2017-2626" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-14 21:15:00 +0000 (Sun, 14 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-11-26 12:50:16 +0000 (Tue, 26 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for libice (DLA-2002-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2002-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libice'
  package(s) announced via the DLA-2002-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It has been found, that libice, an X11 Inter-Client Exchange library,
uses weak entropy to generate keys.

Using arc4random_buf() from libbsd should avoid this flaw." );
	script_tag( name: "affected", value: "'libice' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2:1.0.9-1+deb8u1.

We recommend that you upgrade your libice packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libice-dev", ver: "2:1.0.9-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libice-doc", ver: "2:1.0.9-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libice6", ver: "2:1.0.9-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libice6-dbg", ver: "2:1.0.9-1+deb8u1", rls: "DEB8" ) )){
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

