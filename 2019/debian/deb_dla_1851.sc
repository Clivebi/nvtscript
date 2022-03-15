if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891851" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2015-1239", "CVE-2016-9112", "CVE-2018-20847" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-09 19:57:00 +0000 (Wed, 09 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-07-11 02:00:10 +0000 (Thu, 11 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for openjpeg2 (DLA-1851-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00010.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1851-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/931294" );
	script_xref( name: "URL", value: "https://bugs.debian.org/844551" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the DLA-1851-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two security vulnerabilities were discovered in openjpeg2, a JPEG 2000
image library.

CVE-2016-9112

A floating point exception or divide by zero in the function
opj_pi_next_cprl may lead to a denial-of-service.

CVE-2018-20847

An improper computation of values in the function
opj_get_encoding_parameters can lead to an integer overflow.
This issue was partly fixed by the patch for CVE-2015-1239." );
	script_tag( name: "affected", value: "'openjpeg2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.1.0-2+deb8u7.

We recommend that you upgrade your openjpeg2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7-dbg", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7-dev", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-tools", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d-tools", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d7", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-dec-server", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-server", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-viewer", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip7", ver: "2.1.0-2+deb8u7", rls: "DEB8" ) )){
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

