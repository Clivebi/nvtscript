if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702742" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4248" );
	script_name( "Debian Security Advisory DSA 2742-1 (php5 - interpretation conflict)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-08-26 00:00:00 +0200 (Mon, 26 Aug 2013)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2742.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "php5 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 5.3.3-7+squeeze17.

For the stable distribution (wheezy), this problem has been fixed in
version 5.4.4-14+deb7u4.

For the unstable distribution (sid), this problem has been fixed in
version 5.5.3+dfsg-1.

We recommend that you upgrade your php5 packages." );
	script_tag( name: "summary", value: "It was discovered that PHP, a general-purpose scripting language
commonly used for web application development, did not properly
process embedded NUL characters in the subjectAltName extension of
X.509 certificates. Depending on the application and with
insufficient CA-level checks, this could be abused for impersonating
other users." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-php5filter", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php-pear", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-common", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-curl", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-dbg", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-dev", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-enchant", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-gd", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-gmp", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-imap", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-interbase", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-intl", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-ldap", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mcrypt", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mysql", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-odbc", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-pspell", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-recode", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-sqlite", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-sybase", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-tidy", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.3.3-7+squeeze17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-php5filter", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libphp5-embed", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php-pear", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-common", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-curl", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-dbg", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-dev", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-enchant", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-gd", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-gmp", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-imap", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-interbase", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-intl", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-ldap", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mcrypt", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mysql", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-odbc", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-pspell", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-recode", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-sqlite", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-sybase", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-tidy", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.4.4-14+deb7u4", rls: "DEB7" ) ) != NULL){
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

