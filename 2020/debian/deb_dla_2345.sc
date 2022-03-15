if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892345" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-7068" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 16:03:00 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-08-27 03:00:09 +0000 (Thu, 27 Aug 2020)" );
	script_name( "Debian LTS: Security Advisory for php7.0 (DLA-2345-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/08/msg00043.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2345-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7.0'
  package(s) announced via the DLA-2345-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a use-after-free vulnerability when
parsing PHAR files, a method of putting entire PHP applications into
a single file." );
	script_tag( name: "affected", value: "'php7.0' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
7.0.33-0+deb9u9.

We recommend that you upgrade your php7.0 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php7.0", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libphp7.0-embed", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-bcmath", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-bz2", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-cgi", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-cli", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-common", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-curl", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-dba", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-dev", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-enchant", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-fpm", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-gd", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-gmp", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-imap", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-interbase", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-intl", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-json", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-ldap", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-mbstring", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-mcrypt", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-mysql", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-odbc", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-opcache", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-pgsql", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-phpdbg", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-pspell", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-readline", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-recode", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-snmp", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-soap", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-sqlite3", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-sybase", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-tidy", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-xml", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-xmlrpc", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-xsl", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php7.0-zip", ver: "7.0.33-0+deb9u9", rls: "DEB9" ) )){
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
exit( 0 );

