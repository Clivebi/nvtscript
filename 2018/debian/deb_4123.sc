if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704123" );
	script_version( "2021-06-18T02:36:51+0000" );
	script_cve_id( "CVE-2017-6927", "CVE-2017-6928", "CVE-2017-6929", "CVE-2017-6932" );
	script_name( "Debian Security Advisory DSA 4123-1 (drupal7 - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:36:51 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-24 00:00:00 +0100 (Sat, 24 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-22 13:53:00 +0000 (Thu, 22 Mar 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4123.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 7.32-1+deb8u10.

For the stable distribution (stretch), this problem has been fixed in
version 7.52-2+deb9u2.

We recommend that you upgrade your drupal7 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/drupal7" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found in the Drupal content management
framework." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.32-1+deb8u10", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "drupal7", ver: "7.52-2+deb9u2", rls: "DEB9" ) )){
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

