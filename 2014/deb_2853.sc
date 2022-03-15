if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702853" );
	script_version( "$Revision: 14277 $" );
	script_cve_id( "CVE-2014-1691" );
	script_name( "Debian Security Advisory DSA 2853-1 (horde3 - remote code execution)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:45:38 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-05 00:00:00 +0100 (Wed, 05 Feb 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2853.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "horde3 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 3.3.8+debian0-3.

In the testing (jessie) and unstable (sid) distributions, Horde is
distributed in the php-horde-util package. This problem has been fixed in
version 2.3.0-1.

We recommend that you upgrade your horde3 packages." );
	script_tag( name: "summary", value: "Pedro Ribeiro from Agile Information Security found a possible remote
code execution on Horde3, a web application framework. Unsanitized
variables are passed to the unserialize() PHP function. A remote attacker
could specially-craft one of those variables allowing her to load and
execute code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "horde3", ver: "3.3.8+debian0-3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pear-horde-channel", ver: "3.3.8+debian0-3", rls: "DEB6" ) ) != NULL){
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

