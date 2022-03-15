if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891931" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-13627" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-01 13:25:00 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2019-09-25 02:00:10 +0000 (Wed, 25 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for libgcrypt20 (DLA-1931-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00024.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1931-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/938938" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgcrypt20'
  package(s) announced via the DLA-1931-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a ECDSA timing attack in the
libgcrypt20 cryptographic library." );
	script_tag( name: "affected", value: "'libgcrypt20' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in libgcrypt20 version
1.6.3-2+deb8u6.

We recommend that you upgrade your libgcrypt20 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt20", ver: "1.6.3-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt20-dbg", ver: "1.6.3-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt20-dev", ver: "1.6.3-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt20-doc", ver: "1.6.3-2+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgcrypt11-dev", ver: "1.5.4-3+really1.6.3-2+deb8u6", rls: "DEB8" ) )){
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

