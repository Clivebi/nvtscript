if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702776" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-5652", "CVE-2013-0245", "CVE-2012-0825", "CVE-2013-0244", "CVE-2012-5651", "CVE-2012-5653", "CVE-2012-0826" );
	script_name( "Debian Security Advisory DSA 2776-1 (drupal6 - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-10-11 00:00:00 +0200 (Fri, 11 Oct 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2776.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "drupal6 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 6.28-1.

For the stable distribution (wheezy), these problems have already been
fixed in the drupal7 package.

For the unstable distribution (sid), these problems have already been
fixed in the drupal7 package.

We recommend that you upgrade your drupal6 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been been fixed in the Drupal content
management framework, resulting in information disclosure, insufficient
validation, cross-site scripting and cross-site request forgery." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "drupal6", ver: "6.28-1", rls: "DEB6" ) ) != NULL){
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

