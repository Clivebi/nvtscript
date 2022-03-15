if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892584" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-3410" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-25 18:53:00 +0000 (Thu, 25 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-08 04:00:08 +0000 (Mon, 08 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for libcaca (DLA-2584-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00006.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2584-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2584-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/983684" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libcaca'
  package(s) announced via the DLA-2584-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A buffer overflow issue in caca_resize function in
libcaca/caca/canvas.c may lead to local execution of arbitrary code in
the user context." );
	script_tag( name: "affected", value: "'libcaca' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.99.beta19-2.1~deb9u2.

We recommend that you upgrade your libcaca packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "caca-utils", ver: "0.99.beta19-2.1~deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcaca-dev", ver: "0.99.beta19-2.1~deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcaca0", ver: "0.99.beta19-2.1~deb9u2", rls: "DEB9" ) )){
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

