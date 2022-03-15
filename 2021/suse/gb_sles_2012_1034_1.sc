if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.1034.1" );
	script_cve_id( "CVE-2012-2688", "CVE-2012-3365" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-22 02:29:00 +0000 (Fri, 22 Dec 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:1034-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4|SLES11\\.0SP1|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:1034-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20121034-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php5' package(s) announced via the SUSE-SU-2012:1034-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes two security issues of PHP5:

 * Potential overflow in _php_stream_scandir.
(CVE-2012-2688
> )
 * open_basedir bypass via SQLite extension.
(CVE-2012-3365
> )" );
	script_tag( name: "affected", value: "'php5' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5", rpm: "apache2-mod_php5~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5", rpm: "php5~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath", rpm: "php5-bcmath~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2", rpm: "php5-bz2~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar", rpm: "php5-calendar~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype", rpm: "php5-ctype~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl", rpm: "php5-curl~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba", rpm: "php5-dba~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dbase", rpm: "php5-dbase~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-devel", rpm: "php5-devel~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom", rpm: "php5-dom~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif", rpm: "php5-exif~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi", rpm: "php5-fastcgi~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp", rpm: "php5-ftp~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd", rpm: "php5-gd~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext", rpm: "php5-gettext~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp", rpm: "php5-gmp~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-hash", rpm: "php5-hash~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv", rpm: "php5-iconv~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-imap", rpm: "php5-imap~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json", rpm: "php5-json~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap", rpm: "php5-ldap~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring", rpm: "php5-mbstring~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt", rpm: "php5-mcrypt~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mhash", rpm: "php5-mhash~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql", rpm: "php5-mysql~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ncurses", rpm: "php5-ncurses~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc", rpm: "php5-odbc~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl", rpm: "php5-openssl~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl", rpm: "php5-pcntl~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo", rpm: "php5-pdo~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pear", rpm: "php5-pear~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql", rpm: "php5-pgsql~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-posix", rpm: "php5-posix~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell", rpm: "php5-pspell~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop", rpm: "php5-shmop~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp", rpm: "php5-snmp~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap", rpm: "php5-soap~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sockets", rpm: "php5-sockets~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sqlite", rpm: "php5-sqlite~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin", rpm: "php5-suhosin~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg", rpm: "php5-sysvmsg~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem", rpm: "php5-sysvsem~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm", rpm: "php5-sysvshm~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer", rpm: "php5-tokenizer~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx", rpm: "php5-wddx~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader", rpm: "php5-xmlreader~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc", rpm: "php5-xmlrpc~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl", rpm: "php5-xsl~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib", rpm: "php5-zlib~5.2.14~0.36.1", rls: "SLES10.0SP4" ) )){
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
}
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5", rpm: "apache2-mod_php5~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5", rpm: "php5~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath", rpm: "php5-bcmath~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2", rpm: "php5-bz2~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar", rpm: "php5-calendar~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype", rpm: "php5-ctype~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl", rpm: "php5-curl~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba", rpm: "php5-dba~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dbase", rpm: "php5-dbase~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom", rpm: "php5-dom~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif", rpm: "php5-exif~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi", rpm: "php5-fastcgi~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp", rpm: "php5-ftp~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd", rpm: "php5-gd~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext", rpm: "php5-gettext~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp", rpm: "php5-gmp~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-hash", rpm: "php5-hash~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv", rpm: "php5-iconv~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json", rpm: "php5-json~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap", rpm: "php5-ldap~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring", rpm: "php5-mbstring~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt", rpm: "php5-mcrypt~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql", rpm: "php5-mysql~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc", rpm: "php5-odbc~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl", rpm: "php5-openssl~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl", rpm: "php5-pcntl~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo", rpm: "php5-pdo~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pear", rpm: "php5-pear~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql", rpm: "php5-pgsql~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell", rpm: "php5-pspell~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop", rpm: "php5-shmop~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp", rpm: "php5-snmp~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap", rpm: "php5-soap~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin", rpm: "php5-suhosin~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg", rpm: "php5-sysvmsg~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem", rpm: "php5-sysvsem~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm", rpm: "php5-sysvshm~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer", rpm: "php5-tokenizer~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx", rpm: "php5-wddx~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader", rpm: "php5-xmlreader~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc", rpm: "php5-xmlrpc~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlwriter", rpm: "php5-xmlwriter~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl", rpm: "php5-xsl~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zip", rpm: "php5-zip~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib", rpm: "php5-zlib~5.2.14~0.7.30.42.1", rls: "SLES11.0SP1" ) )){
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
}
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5", rpm: "apache2-mod_php5~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5", rpm: "php5~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath", rpm: "php5-bcmath~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2", rpm: "php5-bz2~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar", rpm: "php5-calendar~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype", rpm: "php5-ctype~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl", rpm: "php5-curl~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba", rpm: "php5-dba~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dbase", rpm: "php5-dbase~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom", rpm: "php5-dom~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif", rpm: "php5-exif~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi", rpm: "php5-fastcgi~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp", rpm: "php5-ftp~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd", rpm: "php5-gd~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext", rpm: "php5-gettext~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp", rpm: "php5-gmp~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-hash", rpm: "php5-hash~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv", rpm: "php5-iconv~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json", rpm: "php5-json~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap", rpm: "php5-ldap~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring", rpm: "php5-mbstring~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt", rpm: "php5-mcrypt~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql", rpm: "php5-mysql~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc", rpm: "php5-odbc~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl", rpm: "php5-openssl~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl", rpm: "php5-pcntl~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo", rpm: "php5-pdo~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pear", rpm: "php5-pear~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql", rpm: "php5-pgsql~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell", rpm: "php5-pspell~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop", rpm: "php5-shmop~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp", rpm: "php5-snmp~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap", rpm: "php5-soap~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin", rpm: "php5-suhosin~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg", rpm: "php5-sysvmsg~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem", rpm: "php5-sysvsem~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm", rpm: "php5-sysvshm~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer", rpm: "php5-tokenizer~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx", rpm: "php5-wddx~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader", rpm: "php5-xmlreader~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc", rpm: "php5-xmlrpc~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlwriter", rpm: "php5-xmlwriter~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl", rpm: "php5-xsl~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zip", rpm: "php5-zip~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib", rpm: "php5-zlib~5.2.14~0.7.30.42.1", rls: "SLES11.0SP2" ) )){
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
}
exit( 0 );

