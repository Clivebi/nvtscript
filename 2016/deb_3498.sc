if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703498" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-3162", "CVE-2016-3163", "CVE-2016-3164", "CVE-2016-3168", "CVE-2016-3169", "CVE-2016-3170" );
	script_name( "Debian Security Advisory DSA 3498-1 (drupal7 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-08 12:37:50 +0530 (Tue, 08 Mar 2016)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3498.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "drupal7 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 7.14-2+deb7u12.

For the stable distribution (jessie), this problem has been fixed in
version 7.32-1+deb8u6.

For the unstable distribution (sid), this problem has been fixed in
version 7.43-1.

We recommend that you upgrade your drupal7 packages." );
	script_tag( name: "summary", value: "Multiple security vulnerabilities have been found in the Drupal content
management framework." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.14-2+deb7u12", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "drupal7", ver: "7.32-1+deb8u6", rls: "DEB8" ) ) != NULL){
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

