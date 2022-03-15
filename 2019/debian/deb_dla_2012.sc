if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892012" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-9232", "CVE-2019-9433" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-24 00:15:00 +0000 (Fri, 24 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-11-27 03:00:17 +0000 (Wed, 27 Nov 2019)" );
	script_name( "Debian LTS: Security Advisory for libvpx (DLA-2012-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/11/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2012-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvpx'
  package(s) announced via the DLA-2012-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found in libvpx, a VP8 and VP9 video codec.

CVE-2019-9232

There is a possible out of bounds read due to a missing bounds check.
This could lead to remote information disclosure with no additional
execution privileges needed. User interaction is not needed for
exploitation.

CVE-2019-9433

There is a possible information disclosure due to improper input
validation. This could lead to remote information disclosure with
no additional execution privileges needed. User interaction is
needed for exploitation." );
	script_tag( name: "affected", value: "'libvpx' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.3.0-3+deb8u2.

We recommend that you upgrade your libvpx packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvpx-dev", ver: "1.3.0-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx-doc", ver: "1.3.0-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx1", ver: "1.3.0-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx1-dbg", ver: "1.3.0-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vpx-tools", ver: "1.3.0-3+deb8u2", rls: "DEB8" ) )){
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

