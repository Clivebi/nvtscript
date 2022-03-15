if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891850" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-10192" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-07-11 02:00:07 +0000 (Thu, 11 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for redis (DLA-1850-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1850-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/931625" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'redis'
  package(s) announced via the DLA-1850-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there were two heap buffer overflows in the
Hyperloglog functionality provided by the Redis in-memory key-value
database." );
	script_tag( name: "affected", value: "'redis' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these issues have been fixed in redis version
2:2.8.17-1+deb8u7.

We recommend that you upgrade your redis packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "redis-server", ver: "2:2.8.17-1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-tools", ver: "2:2.8.17-1+deb8u7", rls: "DEB8" ) )){
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

