if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892717" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-32761" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-30 16:28:00 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-23 03:00:06 +0000 (Fri, 23 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for redis (DLA-2717-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00017.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2717-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2717-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/991375" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'redis'
  package(s) announced via the DLA-2717-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there were several integer overflow issues in
Redis, a popular key-value database system. Some BITFIELD-related
commands were affected on 32-bit systems." );
	script_tag( name: "affected", value: "'redis' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
3:3.2.6-3+deb9u5.

We recommend that you upgrade your redis packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "redis-sentinel", ver: "3:3.2.6-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-server", ver: "3:3.2.6-3+deb9u5", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redis-tools", ver: "3:3.2.6-3+deb9u5", rls: "DEB9" ) )){
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

