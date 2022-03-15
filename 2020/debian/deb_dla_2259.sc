if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892259" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2015-9059" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-28 17:15:00 +0000 (Sun, 28 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-29 03:00:21 +0000 (Mon, 29 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for picocom (DLA-2259-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00030.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2259-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'picocom'
  package(s) announced via the DLA-2259-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a command injection vulnerability in
picocom, a minimal dumb-terminal emulation program." );
	script_tag( name: "affected", value: "'picocom' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.7-1+deb8u1.

We recommend that you upgrade your picocom packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "picocom", ver: "1.7-1+deb8u1", rls: "DEB8" ) )){
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
