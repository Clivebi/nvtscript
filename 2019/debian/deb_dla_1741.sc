if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891741" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2019-9022", "CVE-2019-9637", "CVE-2019-9638", "CVE-2019-9639", "CVE-2019-9640", "CVE-2019-9641" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 18:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)" );
	script_name( "Debian LTS: Security Advisory for php5 (DLA-1741-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00043.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1741-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php5'
  package(s) announced via the DLA-1741-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been found in php5, a server-side,
HTML-embedded scripting language.

CVE-2019-9637
rename() across the device may allow unwanted access during
processing.

CVE-2019-9638, CVE-2019-9639
Uninitialized read in exif_process_IFD_in_MAKERNOTE.

CVE-2019-9640
Invalid Read on exif_process_SOFn.

CVE-2019-9641
Uninitialized read in exif_process_IFD_in_TIFF.

CVE-2019-9022
An issue during parsing of DNS responses allows a hostile DNS server
to misuse memcpy, which leads to a read operation past an allocated
buffer." );
	script_tag( name: "affected", value: "'php5' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
5.6.40+dfsg-0+deb8u2.

We recommend that you upgrade your php5 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php5", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-php5filter", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libphp5-embed", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-pear", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-cgi", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-cli", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-common", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-curl", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-dbg", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-dev", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-enchant", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-fpm", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-gd", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-gmp", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-imap", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-interbase", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-intl", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-ldap", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mcrypt", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mysql", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-mysqlnd", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-odbc", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pgsql", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-phpdbg", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-pspell", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-readline", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-recode", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-snmp", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-sqlite", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-sybase", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-tidy", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-xmlrpc", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-xsl", ver: "5.6.40+dfsg-0+deb8u2", rls: "DEB8" ) )){
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

