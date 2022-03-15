if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704323" );
	script_version( "2019-07-04T09:25:28+0000" );
	script_name( "Debian Security Advisory DSA 4323-1 (drupal7 - security update)" );
	script_tag( name: "last_modification", value: "2019-07-04 09:25:28 +0000 (Thu, 04 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-10-18 00:00:00 +0200 (Thu, 18 Oct 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4323.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 7.52-2+deb9u5.

We recommend that you upgrade your drupal7 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/drupal7" );
	script_tag( name: "summary", value: "Two vulnerabilities were found in Drupal, a fully-featured content
management framework, which could result in arbitrary code execution or
an open redirect." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.52-2+deb9u5", rls: "DEB9" ) )){
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

