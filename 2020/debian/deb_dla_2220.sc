if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892220" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2016-6318" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-05-25 03:00:09 +0000 (Mon, 25 May 2020)" );
	script_name( "Debian LTS: Security Advisory for cracklib2 (DLA-2220-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/05/msg00023.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2220-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cracklib2'
  package(s) announced via the DLA-2220-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a stack-based buffer overflow when
parsing large GECOS fields in cracklib2, a pro-active password checker
library." );
	script_tag( name: "affected", value: "'cracklib2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.9.2-1+deb8u1.

We recommend that you upgrade your cracklib2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cracklib-runtime", ver: "2.9.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcrack2", ver: "2.9.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcrack2-dev", ver: "2.9.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-cracklib", ver: "2.9.2-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-cracklib", ver: "2.9.2-1+deb8u1", rls: "DEB8" ) )){
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

