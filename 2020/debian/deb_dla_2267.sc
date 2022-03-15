if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892267" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-17533" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-01 03:02:36 +0000 (Wed, 01 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for libmatio (DLA-2267-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00037.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2267-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmatio'
  package(s) announced via the DLA-2267-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In libmatio, a library to read and write Matlab MAT files,
a vulnerability was fixed in Mat_VarReadNextInfo4 in mat4.c
that could lead to a heap-based buffer over-read in strdup_vprintf." );
	script_tag( name: "affected", value: "'libmatio' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.5.2-3+deb8u1.

We recommend that you upgrade your libmatio packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libmatio-dev", ver: "1.5.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmatio-doc", ver: "1.5.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmatio2", ver: "1.5.2-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmatio2-dbg", ver: "1.5.2-3+deb8u1", rls: "DEB8" ) )){
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
