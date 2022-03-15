if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892658" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2019-25026", "CVE-2020-36306", "CVE-2020-36307", "CVE-2020-36308", "CVE-2021-30163", "CVE-2021-30164", "CVE-2021-31863", "CVE-2021-31864", "CVE-2021-31865", "CVE-2021-31866" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 18:20:00 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-14 03:02:46 +0000 (Fri, 14 May 2021)" );
	script_name( "Debian LTS: Security Advisory for redmine (DLA-2658-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/05/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2658-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2658-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'redmine'
  package(s) announced via the DLA-2658-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several issues were found in Redmine, a project management web application,
which could lead to cross-site scripting, information disclosure, and reading
arbitrary files from the server." );
	script_tag( name: "affected", value: "'redmine' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
3.3.1-4+deb9u4.

We recommend that you upgrade your redmine packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "redmine", ver: "3.3.1-4+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redmine-mysql", ver: "3.3.1-4+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redmine-pgsql", ver: "3.3.1-4+deb9u4", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "redmine-sqlite", ver: "3.3.1-4+deb9u4", rls: "DEB9" ) )){
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

