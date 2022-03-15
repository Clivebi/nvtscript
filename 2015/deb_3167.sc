if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703167" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2014-9680" );
	script_name( "Debian Security Advisory DSA 3167-1 (sudo - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-22 00:00:00 +0100 (Sun, 22 Feb 2015)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3167.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "sudo on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.8.5p2-1+nmu2.

We recommend that you upgrade your sudo packages." );
	script_tag( name: "summary", value: "Jakub Wilk reported that sudo, a
program designed to provide limited super user privileges to specific users,
preserves the TZ variable from a user's environment without any sanitization. A
user with sudo access may take advantage of this to exploit bugs in the C
library functions which parse the TZ environment variable or to open files that
the user would not otherwise be able to open. The later could potentially cause
changes in system behavior when reading certain device special files or
cause the program run via sudo to block." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "sudo", ver: "1.8.5p2-1+nmu2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sudo-ldap", ver: "1.8.5p2-1+nmu2", rls: "DEB7" ) ) != NULL){
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

