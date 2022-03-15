if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892066" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2019-20326" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 21:45:00 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-17 13:21:50 +0000 (Mon, 17 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for gthumb (DLA-2066-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2066-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gthumb'
  package(s) announced via the DLA-2066-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A heap-based buffer overflow in
_cairo_image_surface_create_from_jpeg() in
extensions/cairo_io/cairo-image-surface-jpeg.c in gThumb and Pix
allows attackers to cause a crash and potentially execute arbitrary
code via a crafted JPEG file." );
	script_tag( name: "affected", value: "'gthumb' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3:3.3.1-2.1+deb8u2.

We recommend that you upgrade your gthumb packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gthumb", ver: "3:3.3.1-2.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gthumb-data", ver: "3:3.3.1-2.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gthumb-dbg", ver: "3:3.3.1-2.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gthumb-dev", ver: "3:3.3.1-2.1+deb8u2", rls: "DEB8" ) )){
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

