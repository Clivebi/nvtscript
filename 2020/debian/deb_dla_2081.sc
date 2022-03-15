if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892081" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-6851" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-02 12:15:00 +0000 (Fri, 02 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-01-29 04:00:04 +0000 (Wed, 29 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for openjpeg2 (DLA-2081-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00025.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2081-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the DLA-2081-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenJPEG had a heap-based buffer overflow in opj_t1_clbl_decode_processor
in libopenjp2.so." );
	script_tag( name: "affected", value: "'openjpeg2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.1.0-2+deb8u9.

We recommend that you upgrade your openjpeg2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7-dbg", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-7-dev", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp2-tools", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d-tools", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjp3d7", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-dec-server", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-server", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip-viewer", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libopenjpip7", ver: "2.1.0-2+deb8u9", rls: "DEB8" ) )){
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

