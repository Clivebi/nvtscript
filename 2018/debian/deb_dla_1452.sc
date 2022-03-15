if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891452" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2016-5836", "CVE-2018-12895" );
	script_name( "Debian LTS: Security Advisory for wordpress (DLA-1452-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-30 00:00:00 +0200 (Mon, 30 Jul 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-20 15:44:00 +0000 (Mon, 20 Aug 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00046.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "wordpress on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.1+dfsg-1+deb8u18.

We recommend that you upgrade your wordpress packages." );
	script_tag( name: "summary", value: "Two vulnerabilities were discovered in wordpress, a web blogging
tool. The Common Vulnerabilities and Exposures project identifies the
following issues.

CVE-2016-5836

The oEmbed protocol implementation in WordPress before 4.5.3 allows
remote attackers to cause a denial of service via unspecified
vectors.

CVE-2018-12895

A vulnerability was discovered in Wordpress, a web blogging tool. It
allowed remote attackers with specific roles to execute arbitrary
code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "wordpress", ver: "4.1+dfsg-1+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-l10n", ver: "4.1+dfsg-1+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfifteen", ver: "4.1+dfsg-1+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentyfourteen", ver: "4.1+dfsg-1+deb8u18", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "wordpress-theme-twentythirteen", ver: "4.1+dfsg-1+deb8u18", rls: "DEB8" ) )){
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

