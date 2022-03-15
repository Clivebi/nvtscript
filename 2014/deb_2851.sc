if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702851" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-1475" );
	script_name( "Debian Security Advisory DSA 2851-1 (drupal6 - impersonation)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-02 00:00:00 +0100 (Sun, 02 Feb 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2851.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "drupal6 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 6.30-1.

We recommend that you upgrade your drupal6 packages." );
	script_tag( name: "summary", value: "Christian Mainka and Vladislav Mladenov reported a vulnerability in the
OpenID module of Drupal, a fully-featured content management framework.
A malicious user could exploit this flaw to log in as other users on the
site, including administrators, and hijack their accounts.

These fixes require extra updates to the database which can be done from
the administration pages." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "drupal6", ver: "6.30-1", rls: "DEB6" ) ) != NULL){
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

