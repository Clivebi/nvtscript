if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892147" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2019-17546" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-03-19 04:00:10 +0000 (Thu, 19 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for gdal (DLA-2147-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00020.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2147-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdal'
  package(s) announced via the DLA-2147-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "tif_getimage.c in LibTIFF, as used in GDAL has an integer overflow
that potentially causes a heap-based buffer overflow via a crafted
RGBA image, related to a 'Negative-size-param' condition." );
	script_tag( name: "affected", value: "'gdal' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.10.1+dfsg-8+deb8u2.

We recommend that you upgrade your gdal packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gdal-bin", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdal-dev", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdal-doc", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdal-java", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdal-perl", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdal1-dev", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgdal1h", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-gdal", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-gdal", ver: "1.10.1+dfsg-8+deb8u2", rls: "DEB8" ) )){
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

