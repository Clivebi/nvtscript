if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703017" );
	script_version( "2020-02-17T08:23:05+0000" );
	script_cve_id( "CVE-2014-4172" );
	script_name( "Debian Security Advisory DSA 3017-1 (php-cas - security update)" );
	script_tag( name: "last_modification", value: "2020-02-17 08:23:05 +0000 (Mon, 17 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-09-02 00:00:00 +0200 (Tue, 02 Sep 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "php-cas on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.3.1-4+deb7u1.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your php-cas packages." );
	script_tag( name: "summary", value: "Marvin S. Addison discovered that Jasig phpCAS, a PHP library for the
CAS authentication protocol, did not encode tickets before adding them
to an URL, creating a possibility for cross site scripting." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "php-cas", ver: "1.3.1-4+deb7u1", rls: "DEB7" ) ) != NULL){
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

