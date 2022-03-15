if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891895" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2019-1010305" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-23 23:15:00 +0000 (Fri, 23 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-24 02:00:06 +0000 (Sat, 24 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for libmspack (DLA-1895-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1895-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmspack'
  package(s) announced via the DLA-1895-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "JsHuang found an issue in libmspack, a library for Microsoft compression
format.
Opening a crafted chm file might result in a buffer overflow which might
disclose confidential information." );
	script_tag( name: "affected", value: "'libmspack' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.5-1+deb8u4.

We recommend that you upgrade your libmspack packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmspack-dbg", ver: "0.5-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmspack-dev", ver: "0.5-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmspack-doc", ver: "0.5-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmspack0", ver: "0.5-1+deb8u4", rls: "DEB8" ) )){
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

