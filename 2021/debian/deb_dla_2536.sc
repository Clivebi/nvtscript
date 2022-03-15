if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892536" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2019-13616", "CVE-2019-7575", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635", "CVE-2019-7636", "CVE-2019-7638", "CVE-2020-14409", "CVE-2020-14410" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 14:59:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-31 04:00:11 +0000 (Sun, 31 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for libsdl2 (DLA-2536-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00024.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2536-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2536-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsdl2'
  package(s) announced via the DLA-2536-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues have been found in libsdl2, a library for portable low
level access to a video framebuffer, audio output, mouse, and keyboard.
All issues are related to either buffer overflow, integer overflow or
heap-based buffer over-read, resulting in a DoS or remote code execution
by using crafted files of different formats." );
	script_tag( name: "affected", value: "'libsdl2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
2.0.5+dfsg1-2+deb9u1.

We recommend that you upgrade your libsdl2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-2.0-0", ver: "2.0.5+dfsg1-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-dev", ver: "2.0.5+dfsg1-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl2-doc", ver: "2.0.5+dfsg1-2+deb9u1", rls: "DEB9" ) )){
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

