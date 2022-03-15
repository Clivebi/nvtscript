if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704081" );
	script_version( "2021-06-18T02:36:51+0000" );
	script_cve_id( "CVE-2017-11142", "CVE-2017-11143", "CVE-2017-11144", "CVE-2017-11145", "CVE-2017-11628", "CVE-2017-12933", "CVE-2017-16642" );
	script_name( "Debian Security Advisory DSA 4081-1 (php5 - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:36:51 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-08 00:00:00 +0100 (Mon, 08 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-14 02:29:00 +0000 (Sun, 14 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4081.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "php5 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 5.6.33+dfsg-0+deb8u1.

We recommend that you upgrade your php5 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/php5" );
	script_tag( name: "summary", value: "Several vulnerabilities were found in PHP, a widely-used open source
general purpose scripting language:

CVE-2017-11142
Denial of service via overly long form variables

CVE-2017-11143
Invalid free() in wddx_deserialize()

CVE-2017-11144
Denial of service in openssl extension due to incorrect return value
check of OpenSSL sealing function.

CVE-2017-11145
Out-of-bounds read in wddx_deserialize()

CVE-2017-11628
Buffer overflow in PHP INI parsing API

CVE-2017-12933
Buffer overread in finish_nested_data()

CVE-2017-16642
Out-of-bounds read in timelib_meridian()" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php5filter", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libphp5-embed", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-cli", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-common", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-curl", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-dbg", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-dev", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-enchant", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-gd", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-gmp", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-imap", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-interbase", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-intl", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-ldap", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mcrypt", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mysql", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-odbc", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-phpdbg", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pspell", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-readline", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-recode", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-sqlite", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-sybase", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-tidy", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.6.33+dfsg-0+deb8u1", rls: "DEB8" ) )){
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

