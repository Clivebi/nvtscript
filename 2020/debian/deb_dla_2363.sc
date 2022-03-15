if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892363" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-17446" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-03 01:15:00 +0000 (Thu, 03 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-03 03:00:11 +0000 (Thu, 03 Sep 2020)" );
	script_name( "Debian LTS: Security Advisory for asyncpg (DLA-2363-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/09/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2363-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'asyncpg'
  package(s) announced via the DLA-2363-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "asyncpg before 0.21.0 allows a malicious PostgreSQL server to trigger
a crash or execute arbitrary code (on a database client) via a crafted
server response, because of access to an uninitialized pointer in the
array data decoder." );
	script_tag( name: "affected", value: "'asyncpg' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
0.8.4-1+deb9u1.

We recommend that you upgrade your asyncpg packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python3-asyncpg", ver: "0.8.4-1+deb9u1", rls: "DEB9" ) )){
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

