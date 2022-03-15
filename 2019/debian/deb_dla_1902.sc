if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891902" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2019-15142", "CVE-2019-15143", "CVE-2019-15144", "CVE-2019-15145" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-27 16:40:00 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2019-08-30 02:00:11 +0000 (Fri, 30 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for djvulibre (DLA-1902-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00036.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1902-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'djvulibre'
  package(s) announced via the DLA-1902-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Hongxu Chen found several issues in djvulibre, a library and set of tools
to handle images in the DjVu format.

The issues are a heap-buffer-overflow, a stack-overflow, an infinite loop
and an invalid read when working with crafted files as input." );
	script_tag( name: "affected", value: "'djvulibre' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.5.25.4-4+deb8u1.

We recommend that you upgrade your djvulibre packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "djview", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djview3", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djvulibre-bin", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djvulibre-dbg", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djvulibre-desktop", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djvuserve", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdjvulibre-dev", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdjvulibre-text", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdjvulibre21", ver: "3.5.25.4-4+deb8u1", rls: "DEB8" ) )){
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

