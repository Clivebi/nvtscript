if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892657" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-3520" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-13 03:00:07 +0000 (Thu, 13 May 2021)" );
	script_name( "Debian LTS: Security Advisory for lz4 (DLA-2657-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/05/msg00012.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2657-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2657-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/987856" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lz4'
  package(s) announced via the DLA-2657-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a potential memory corruption
vulnerability in the lz4 compression algorithm library." );
	script_tag( name: "affected", value: "'lz4' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
0.0~r131-2+deb9u1.

We recommend that you upgrade your lz4 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblz4-1", ver: "0.0~r131-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblz4-1-dbg", ver: "0.0~r131-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblz4-dev", ver: "0.0~r131-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblz4-tool", ver: "0.0~r131-2+deb9u1", rls: "DEB9" ) )){
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

