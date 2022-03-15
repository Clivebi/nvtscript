if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892196" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2016-10711" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-30 18:15:00 +0000 (Thu, 30 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-05-01 03:00:14 +0000 (Fri, 01 May 2020)" );
	script_name( "Debian LTS: Security Advisory for pound (DLA-2196-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2196-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pound'
  package(s) announced via the DLA-2196-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in pound,
A request smuggling vulnerability was discovered in pound, a reverse proxy,
load balancer and HTTPS front-end for Web servers, that may allow

attackers to send a specially crafted http request to a web server or
reverse proxy while pound may see a different set of requests.
This facilitates several possible exploitations, such as partial cache
poisoning, bypassing firewall protection and XSS." );
	script_tag( name: "affected", value: "'pound' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.6-6+deb8u2.

We recommend that you upgrade your pound packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "pound", ver: "2.6-6+deb8u2", rls: "DEB8" ) )){
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

