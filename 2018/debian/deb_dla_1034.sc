if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891034" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2016-10397", "CVE-2017-11143", "CVE-2017-11144", "CVE-2017-11145", "CVE-2017-11147" );
	script_name( "Debian LTS: Security Advisory for php5 (DLA-1034-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-08 00:00:00 +0100 (Thu, 08 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00026.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "php5 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
5.4.45-0+deb7u9.

We recommend that you upgrade your php5 packages." );
	script_tag( name: "summary", value: "Several issues have been discovered in PHP (recursive acronym for PHP:
Hypertext Preprocessor), a widely-used open source general-purpose
scripting language that is especially suited for web development and can
be embedded into HTML.

CVE-2016-10397
Incorrect handling of various URI components in the URL parser could
be used by attackers to bypass hostname-specific URL checks.

CVE-2017-11143
An invalid free in the WDDX deserialization of boolean parameters
could be used by attackers able to inject XML for deserialization to
crash the PHP interpreter.

CVE-2017-11144
The openssl extension PEM sealing code did not check the return value
of the OpenSSL sealing function, which could lead to a crash of the
PHP interpreter.

CVE-2017-11145
Lack of a bounds check in the date extension's timelib_meridian
parsing code could be used by attackers able to supply date strings to
leak information from the interpreter.

CVE-2017-11147
The PHAR archive handler could be used by attackers supplying
malicious archive files to crash the PHP interpreter or potentially
disclose information due to a buffer over-read in the
phar_parse_pharfile function in ext/phar/phar.c." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php5filter", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libphp5-embed", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-cli", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-common", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-curl", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-dbg", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-dev", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-enchant", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-gd", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-gmp", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-imap", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-interbase", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-intl", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-ldap", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mcrypt", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mysql", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-odbc", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pspell", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-recode", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-sqlite", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-sybase", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-tidy", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.4.45-0+deb7u9", rls: "DEB7" ) )){
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

