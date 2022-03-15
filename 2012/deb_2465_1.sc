if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71344" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-1172", "CVE-2012-1823", "CVE-2012-2311" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:43:29 -0400 (Thu, 31 May 2012)" );
	script_name( "Debian Security Advisory DSA 2465-1 (php5)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202465-1" );
	script_tag( name: "insight", value: "De Eindbazen discovered that PHP, when run with mod_cgi, will
interpret a query string as command line parameters, allowing to
execute arbitrary code.

Additionally, this update fixes insufficient validation of upload
name which lead to corrupted $_FILES indices.

For the stable distribution (squeeze), this problem has been fixed in
version 5.3.3-7+squeeze9.

The testing distribution (wheezy) will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 5.4.3-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your php5 packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to php5
announced via advisory DSA 2465-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-php5filter", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php-pear", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-common", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-curl", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-dbg", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-dev", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-enchant", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-gd", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-gmp", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-imap", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-interbase", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-intl", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-ldap", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mcrypt", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mysql", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-odbc", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-pspell", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-recode", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-sqlite", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-sybase", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-tidy", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.3.3-7+squeeze9", rls: "DEB6" ) ) != NULL){
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

