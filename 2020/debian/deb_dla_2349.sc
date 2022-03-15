if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892349" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2017-16907" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-29 21:15:00 +0000 (Sat, 29 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-30 03:00:25 +0000 (Sun, 30 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for php-horde (DLA-2349-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00046.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2349-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/909739" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-horde'
  package(s) announced via the DLA-2349-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Horde Groupware, there has been an XSS vulnerability in two components
via the Color field in a Create Task List action." );
	script_tag( name: "affected", value: "'php-horde' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
5.2.13+debian0-1+deb9u3.

We recommend that you upgrade your php-horde packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-horde", ver: "5.2.13+debian0-1+deb9u3", rls: "DEB9" ) )){
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

