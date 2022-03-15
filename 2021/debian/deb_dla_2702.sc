if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892702" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-3630" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 03:15:00 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-04 03:00:19 +0000 (Sun, 04 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for djvulibre (DLA-2702-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2702-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2702-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'djvulibre'
  package(s) announced via the DLA-2702-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An out-of-bounds write vulnerability was found in DjVuLibre in
DJVU::DjVuTXT::decode() in DjVuText.cpp via a crafted djvu file
which may lead to crash and segmentation fault." );
	script_tag( name: "affected", value: "'djvulibre' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
3.5.27.1-7+deb9u2.

We recommend that you upgrade your djvulibre packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "djview", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djview3", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djvulibre-bin", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djvulibre-dbg", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djvulibre-desktop", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "djvuserve", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdjvulibre-dev", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdjvulibre-text", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libdjvulibre21", ver: "3.5.27.1-7+deb9u2", rls: "DEB9" ) )){
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

