if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892682" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-33477" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-09 15:15:00 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-10 03:00:12 +0000 (Thu, 10 Jun 2021)" );
	script_name( "Debian LTS: Security Advisory for mrxvt (DLA-2682-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/06/msg00011.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2682-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2682-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mrxvt'
  package(s) announced via the DLA-2682-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "mrxvt, lightweight multi-tabbed X terminal emulator, allowed
(potentially remote) code execution because of improper handling
of certain escape sequences (ESC G Q)." );
	script_tag( name: "affected", value: "'mrxvt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.5.4-2+deb9u1.

We recommend that you upgrade your mrxvt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mrxvt", ver: "0.5.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mrxvt-cjk", ver: "0.5.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mrxvt-common", ver: "0.5.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mrxvt-mini", ver: "0.5.4-2+deb9u1", rls: "DEB9" ) )){
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

