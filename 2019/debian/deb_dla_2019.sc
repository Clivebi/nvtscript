if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892019" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-17402" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-21 17:15:00 +0000 (Mon, 21 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-12-03 03:00:07 +0000 (Tue, 03 Dec 2019)" );
	script_name( "Debian LTS: Security Advisory for exiv2 (DLA-2019-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/12/msg00001.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2019-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'exiv2'
  package(s) announced via the DLA-2019-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A corrupted or specially crafted CRW images might exceed the overall
buffersize to cause a denial of service." );
	script_tag( name: "affected", value: "'exiv2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.24-4.1+deb8u5.

We recommend that you upgrade your exiv2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "exiv2", ver: "0.24-4.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-13", ver: "0.24-4.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dbg", ver: "0.24-4.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dev", ver: "0.24-4.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-doc", ver: "0.24-4.1+deb8u5", rls: "DEB8" ) )){
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

