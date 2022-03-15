if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703973" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_cve_id( "CVE-2017-14313" );
	script_name( "Debian Security Advisory DSA 3973-1 (wordpress-shibboleth - security update)" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-14 00:00:00 +0200 (Thu, 14 Sep 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3973.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "wordpress-shibboleth on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.4-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.4-2+deb9u1.

We recommend that you upgrade your wordpress-shibboleth packages." );
	script_tag( name: "summary", value: "A cross-site-scripting vulnerability has been discovered in the login
form of the Shibboleth identity provider module for Wordpress." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "wordpress-shibboleth", ver: "1.4-2+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "wordpress-shibboleth", ver: "1.4-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

