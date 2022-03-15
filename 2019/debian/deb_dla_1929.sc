if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891929" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2016-7398" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-20 21:15:00 +0000 (Fri, 20 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-21 02:00:24 +0000 (Sat, 21 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for php-pecl-http (DLA-1929-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00022.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1929-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-pecl-http'
  package(s) announced via the DLA-1929-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability has been discovered in php-pecl-http, the pecl_http
module for PHP 5 Extended HTTP Support. A type confusion vulnerability
in the merge_param() function allows attackers to crash PHP and possibly
execute arbitrary code via crafted HTTP requests." );
	script_tag( name: "affected", value: "'php-pecl-http' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.0.4-1+deb8u1.

We recommend that you upgrade your php-pecl-http packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php5-pecl-http", ver: "2.0.4-1+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pecl-http-dev", ver: "2.0.4-1+deb8u1", rls: "DEB8" ) )){
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

