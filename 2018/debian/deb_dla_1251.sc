if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891251" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2018-5712" );
	script_name( "Debian LTS: Security Advisory for php5 (DLA-1251-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-22 00:00:00 +0100 (Mon, 22 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/01/msg00025.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "php5 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
5.4.45-0+deb7u12.

We recommend that you upgrade your php5 packages." );
	script_tag( name: "summary", value: "It was discovered that PHP5 was vulnerable to a reflected cross-site
scripting (XSS) attack on the PHAR 404 error page by manipulating the
URI of a request for a .phar file. This issue is only exploitable if
the web server is configured to handle phar files using PHP5." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php5filter", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libphp5-embed", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-cli", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-common", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-curl", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-dbg", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-dev", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-enchant", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-gd", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-gmp", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-imap", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-interbase", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-intl", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-ldap", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mcrypt", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mysql", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-odbc", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pspell", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-recode", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-sqlite", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-sybase", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-tidy", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.4.45-0+deb7u12", rls: "DEB7" ) )){
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

