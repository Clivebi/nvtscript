if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892180" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-11736" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-14 02:15:00 +0000 (Mon, 14 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-04-18 03:00:15 +0000 (Sat, 18 Apr 2020)" );
	script_name( "Debian LTS: Security Advisory for file-roller (DLA-2180-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2180-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/956638" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'file-roller'
  package(s) announced via the DLA-2180-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "fr-archive-libarchive.c in GNOME file-roller through 3.36.1 allows
Directory Traversal during extraction because it lacks a check of
whether a file's parent is a symlink to a directory outside of the
intended extraction location." );
	script_tag( name: "affected", value: "'file-roller' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.14.1-1+deb8u2.

We recommend that you upgrade your file-roller packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "file-roller", ver: "3.14.1-1+deb8u2", rls: "DEB8" ) )){
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

