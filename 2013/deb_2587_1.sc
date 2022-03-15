if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702587" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-5526" );
	script_name( "Debian Security Advisory DSA 2587-1 (libcgi-pm-perl - HTTP header injection)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2587.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "libcgi-pm-perl on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 3.49-1squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 3.61-2.

We recommend that you upgrade your libcgi-pm-perl packages." );
	script_tag( name: "summary", value: "It was discovered that the CGI module for Perl does not filter LF
characters in the Set-Cookie and P3P headers, potentially allowing
attackers to inject HTTP headers." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libcgi-pm-perl", ver: "3.49-1squeeze2", rls: "DEB6" ) ) != NULL){
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

