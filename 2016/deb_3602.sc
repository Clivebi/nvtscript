if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703602" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2013-7456", "CVE-2016-3074", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096" );
	script_name( "Debian Security Advisory DSA 3602-1 (php5 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-06-14 00:00:00 +0200 (Tue, 14 Jun 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3602.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "php5 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 5.6.22+dfsg-0+deb8u1.

We recommend that you upgrade your php5 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were found in PHP,
a general-purpose scripting language commonly used for web application development.

The vulnerabilities are addressed by upgrading PHP to the new upstream
version 5.6.22, which includes additional bug fixes." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-php5filter", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libphp5-embed", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php-pear", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-cli", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-common", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-curl", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-dbg", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-dev", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-enchant", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-gd", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-gmp", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-imap", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-interbase", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-intl", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-ldap", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mcrypt", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mysql", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-odbc", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-phpdbg", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-pspell", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-readline", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-recode", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-sqlite", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-sybase", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-tidy", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.6.22+dfsg-0+deb8u1", rls: "DEB8" ) ) != NULL){
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

