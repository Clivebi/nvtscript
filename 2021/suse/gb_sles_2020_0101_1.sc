if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0101.1" );
	script_cve_id( "CVE-2019-11045", "CVE-2019-11046", "CVE-2019-11047", "CVE-2019-11050" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:10 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-17 04:15:00 +0000 (Sun, 17 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0101-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0101-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200101-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php7' package(s) announced via the SUSE-SU-2020:0101-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for php7 fixes the following issues:
CVE-2019-11045: Fixed an issue with improper input validation in the
 filename handling of the DirectoryIterator class (bsc#1159923).

CVE-2019-11046: Fixed an information leak in bc_shift_addsub()
 (bsc#1159924).

CVE-2019-11047, CVE-2019-11050: Fixed multiple information leaks in
 exif_read_data() (bsc#1159922, bsc#1159927)." );
	script_tag( name: "affected", value: "'php7' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Packagehub Subpackages 15, SUSE Linux Enterprise Module for Web Scripting 15, SUSE Linux Enterprise Module for Web Scripting 15-SP1." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "php7-debuginfo", rpm: "php7-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-debugsource", rpm: "php7-debugsource~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-embed", rpm: "php7-embed~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-embed-debuginfo", rpm: "php7-embed-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php7", rpm: "apache2-mod_php7~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php7-debuginfo", rpm: "apache2-mod_php7-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7", rpm: "php7~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-bcmath", rpm: "php7-bcmath~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-bcmath-debuginfo", rpm: "php7-bcmath-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-bz2", rpm: "php7-bz2~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-bz2-debuginfo", rpm: "php7-bz2-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-calendar", rpm: "php7-calendar~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-calendar-debuginfo", rpm: "php7-calendar-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ctype", rpm: "php7-ctype~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ctype-debuginfo", rpm: "php7-ctype-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-curl", rpm: "php7-curl~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-curl-debuginfo", rpm: "php7-curl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-dba", rpm: "php7-dba~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-dba-debuginfo", rpm: "php7-dba-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-devel", rpm: "php7-devel~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-dom", rpm: "php7-dom~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-dom-debuginfo", rpm: "php7-dom-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-enchant", rpm: "php7-enchant~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-enchant-debuginfo", rpm: "php7-enchant-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-exif", rpm: "php7-exif~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-exif-debuginfo", rpm: "php7-exif-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fastcgi", rpm: "php7-fastcgi~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fastcgi-debuginfo", rpm: "php7-fastcgi-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fileinfo", rpm: "php7-fileinfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fileinfo-debuginfo", rpm: "php7-fileinfo-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fpm", rpm: "php7-fpm~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fpm-debuginfo", rpm: "php7-fpm-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ftp", rpm: "php7-ftp~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ftp-debuginfo", rpm: "php7-ftp-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gd", rpm: "php7-gd~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gd-debuginfo", rpm: "php7-gd-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gettext", rpm: "php7-gettext~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gettext-debuginfo", rpm: "php7-gettext-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gmp", rpm: "php7-gmp~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gmp-debuginfo", rpm: "php7-gmp-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-iconv", rpm: "php7-iconv~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-iconv-debuginfo", rpm: "php7-iconv-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-intl", rpm: "php7-intl~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-intl-debuginfo", rpm: "php7-intl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-json", rpm: "php7-json~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-json-debuginfo", rpm: "php7-json-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ldap", rpm: "php7-ldap~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ldap-debuginfo", rpm: "php7-ldap-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-mbstring", rpm: "php7-mbstring~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-mbstring-debuginfo", rpm: "php7-mbstring-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-mysql", rpm: "php7-mysql~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-mysql-debuginfo", rpm: "php7-mysql-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-odbc", rpm: "php7-odbc~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-odbc-debuginfo", rpm: "php7-odbc-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-opcache", rpm: "php7-opcache~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-opcache-debuginfo", rpm: "php7-opcache-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-openssl", rpm: "php7-openssl~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-openssl-debuginfo", rpm: "php7-openssl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pcntl", rpm: "php7-pcntl~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pcntl-debuginfo", rpm: "php7-pcntl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pdo", rpm: "php7-pdo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pdo-debuginfo", rpm: "php7-pdo-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pear", rpm: "php7-pear~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pear-Archive_Tar", rpm: "php7-pear-Archive_Tar~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pgsql", rpm: "php7-pgsql~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pgsql-debuginfo", rpm: "php7-pgsql-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-phar", rpm: "php7-phar~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-phar-debuginfo", rpm: "php7-phar-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-posix", rpm: "php7-posix~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-posix-debuginfo", rpm: "php7-posix-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-shmop", rpm: "php7-shmop~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-shmop-debuginfo", rpm: "php7-shmop-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-snmp", rpm: "php7-snmp~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-snmp-debuginfo", rpm: "php7-snmp-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-soap", rpm: "php7-soap~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-soap-debuginfo", rpm: "php7-soap-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sockets", rpm: "php7-sockets~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sockets-debuginfo", rpm: "php7-sockets-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sodium", rpm: "php7-sodium~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sodium-debuginfo", rpm: "php7-sodium-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sqlite", rpm: "php7-sqlite~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sqlite-debuginfo", rpm: "php7-sqlite-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvmsg", rpm: "php7-sysvmsg~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvmsg-debuginfo", rpm: "php7-sysvmsg-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvsem", rpm: "php7-sysvsem~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvsem-debuginfo", rpm: "php7-sysvsem-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvshm", rpm: "php7-sysvshm~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvshm-debuginfo", rpm: "php7-sysvshm-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-tokenizer", rpm: "php7-tokenizer~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-tokenizer-debuginfo", rpm: "php7-tokenizer-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-wddx", rpm: "php7-wddx~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-wddx-debuginfo", rpm: "php7-wddx-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlreader", rpm: "php7-xmlreader~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlreader-debuginfo", rpm: "php7-xmlreader-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlrpc", rpm: "php7-xmlrpc~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlrpc-debuginfo", rpm: "php7-xmlrpc-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlwriter", rpm: "php7-xmlwriter~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlwriter-debuginfo", rpm: "php7-xmlwriter-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xsl", rpm: "php7-xsl~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xsl-debuginfo", rpm: "php7-xsl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-zip", rpm: "php7-zip~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-zip-debuginfo", rpm: "php7-zip-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-zlib", rpm: "php7-zlib~7.2.5~4.49.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-zlib-debuginfo", rpm: "php7-zlib-debuginfo~7.2.5~4.49.1", rls: "SLES15.0" ) )){
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php7", rpm: "apache2-mod_php7~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php7-debuginfo", rpm: "apache2-mod_php7-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7", rpm: "php7~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-bcmath", rpm: "php7-bcmath~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-bcmath-debuginfo", rpm: "php7-bcmath-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-bz2", rpm: "php7-bz2~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-bz2-debuginfo", rpm: "php7-bz2-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-calendar", rpm: "php7-calendar~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-calendar-debuginfo", rpm: "php7-calendar-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ctype", rpm: "php7-ctype~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ctype-debuginfo", rpm: "php7-ctype-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-curl", rpm: "php7-curl~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-curl-debuginfo", rpm: "php7-curl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-dba", rpm: "php7-dba~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-dba-debuginfo", rpm: "php7-dba-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-debuginfo", rpm: "php7-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-debugsource", rpm: "php7-debugsource~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-devel", rpm: "php7-devel~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-dom", rpm: "php7-dom~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-dom-debuginfo", rpm: "php7-dom-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-enchant", rpm: "php7-enchant~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-enchant-debuginfo", rpm: "php7-enchant-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-exif", rpm: "php7-exif~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-exif-debuginfo", rpm: "php7-exif-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fastcgi", rpm: "php7-fastcgi~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fastcgi-debuginfo", rpm: "php7-fastcgi-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fileinfo", rpm: "php7-fileinfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fileinfo-debuginfo", rpm: "php7-fileinfo-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fpm", rpm: "php7-fpm~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-fpm-debuginfo", rpm: "php7-fpm-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ftp", rpm: "php7-ftp~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ftp-debuginfo", rpm: "php7-ftp-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gd", rpm: "php7-gd~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gd-debuginfo", rpm: "php7-gd-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gettext", rpm: "php7-gettext~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gettext-debuginfo", rpm: "php7-gettext-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gmp", rpm: "php7-gmp~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-gmp-debuginfo", rpm: "php7-gmp-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-iconv", rpm: "php7-iconv~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-iconv-debuginfo", rpm: "php7-iconv-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-intl", rpm: "php7-intl~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-intl-debuginfo", rpm: "php7-intl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-json", rpm: "php7-json~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-json-debuginfo", rpm: "php7-json-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ldap", rpm: "php7-ldap~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-ldap-debuginfo", rpm: "php7-ldap-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-mbstring", rpm: "php7-mbstring~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-mbstring-debuginfo", rpm: "php7-mbstring-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-mysql", rpm: "php7-mysql~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-mysql-debuginfo", rpm: "php7-mysql-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-odbc", rpm: "php7-odbc~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-odbc-debuginfo", rpm: "php7-odbc-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-opcache", rpm: "php7-opcache~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-opcache-debuginfo", rpm: "php7-opcache-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-openssl", rpm: "php7-openssl~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-openssl-debuginfo", rpm: "php7-openssl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pcntl", rpm: "php7-pcntl~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pcntl-debuginfo", rpm: "php7-pcntl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pdo", rpm: "php7-pdo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pdo-debuginfo", rpm: "php7-pdo-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pear", rpm: "php7-pear~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pear-Archive_Tar", rpm: "php7-pear-Archive_Tar~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pgsql", rpm: "php7-pgsql~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-pgsql-debuginfo", rpm: "php7-pgsql-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-phar", rpm: "php7-phar~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-phar-debuginfo", rpm: "php7-phar-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-posix", rpm: "php7-posix~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-posix-debuginfo", rpm: "php7-posix-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-shmop", rpm: "php7-shmop~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-shmop-debuginfo", rpm: "php7-shmop-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-snmp", rpm: "php7-snmp~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-snmp-debuginfo", rpm: "php7-snmp-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-soap", rpm: "php7-soap~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-soap-debuginfo", rpm: "php7-soap-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sockets", rpm: "php7-sockets~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sockets-debuginfo", rpm: "php7-sockets-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sodium", rpm: "php7-sodium~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sodium-debuginfo", rpm: "php7-sodium-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sqlite", rpm: "php7-sqlite~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sqlite-debuginfo", rpm: "php7-sqlite-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvmsg", rpm: "php7-sysvmsg~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvmsg-debuginfo", rpm: "php7-sysvmsg-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvsem", rpm: "php7-sysvsem~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvsem-debuginfo", rpm: "php7-sysvsem-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvshm", rpm: "php7-sysvshm~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-sysvshm-debuginfo", rpm: "php7-sysvshm-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-tokenizer", rpm: "php7-tokenizer~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-tokenizer-debuginfo", rpm: "php7-tokenizer-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-wddx", rpm: "php7-wddx~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-wddx-debuginfo", rpm: "php7-wddx-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlreader", rpm: "php7-xmlreader~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlreader-debuginfo", rpm: "php7-xmlreader-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlrpc", rpm: "php7-xmlrpc~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlrpc-debuginfo", rpm: "php7-xmlrpc-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlwriter", rpm: "php7-xmlwriter~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xmlwriter-debuginfo", rpm: "php7-xmlwriter-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xsl", rpm: "php7-xsl~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-xsl-debuginfo", rpm: "php7-xsl-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-zip", rpm: "php7-zip~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-zip-debuginfo", rpm: "php7-zip-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-zlib", rpm: "php7-zlib~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php7-zlib-debuginfo", rpm: "php7-zlib-debuginfo~7.2.5~4.49.1", rls: "SLES15.0SP1" ) )){
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
