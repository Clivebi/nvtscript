if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850217" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2012-12-13 17:01:21 +0530 (Thu, 13 Dec 2012)" );
	script_cve_id( "CVE-2011-1466", "CVE-2011-4153", "CVE-2011-4566", "CVE-2011-4885", "CVE-2012-0057", "CVE-2012-0781", "CVE-2012-0788", "CVE-2012-0789", "CVE-2012-0807", "CVE-2012-0830", "CVE-2012-0831" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "openSUSE-SU", value: "2012:0426-1" );
	script_name( "openSUSE: Security Advisory for update (openSUSE-SU-2012:0426-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.1" );
	script_tag( name: "affected", value: "update on openSUSE 12.1" );
	script_tag( name: "insight", value: "php5 security update" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(release == "openSUSE12.1"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5", rpm: "apache2-mod_php5~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5-debuginfo", rpm: "apache2-mod_php5-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5", rpm: "php5~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath", rpm: "php5-bcmath~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath-debuginfo", rpm: "php5-bcmath-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2", rpm: "php5-bz2~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2-debuginfo", rpm: "php5-bz2-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar", rpm: "php5-calendar~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar-debuginfo", rpm: "php5-calendar-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype", rpm: "php5-ctype~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype-debuginfo", rpm: "php5-ctype-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl", rpm: "php5-curl~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl-debuginfo", rpm: "php5-curl-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba", rpm: "php5-dba~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba-debuginfo", rpm: "php5-dba-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-debuginfo", rpm: "php5-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-debugsource", rpm: "php5-debugsource~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-devel", rpm: "php5-devel~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom", rpm: "php5-dom~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom-debuginfo", rpm: "php5-dom-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-enchant", rpm: "php5-enchant~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-enchant-debuginfo", rpm: "php5-enchant-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif", rpm: "php5-exif~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif-debuginfo", rpm: "php5-exif-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi", rpm: "php5-fastcgi~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi-debuginfo", rpm: "php5-fastcgi-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fileinfo", rpm: "php5-fileinfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fileinfo-debuginfo", rpm: "php5-fileinfo-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fpm", rpm: "php5-fpm~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fpm-debuginfo", rpm: "php5-fpm-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp", rpm: "php5-ftp~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp-debuginfo", rpm: "php5-ftp-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd", rpm: "php5-gd~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd-debuginfo", rpm: "php5-gd-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext", rpm: "php5-gettext~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext-debuginfo", rpm: "php5-gettext-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp", rpm: "php5-gmp~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp-debuginfo", rpm: "php5-gmp-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv", rpm: "php5-iconv~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv-debuginfo", rpm: "php5-iconv-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-imap", rpm: "php5-imap~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-imap-debuginfo", rpm: "php5-imap-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-intl", rpm: "php5-intl~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-intl-debuginfo", rpm: "php5-intl-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json", rpm: "php5-json~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json-debuginfo", rpm: "php5-json-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap", rpm: "php5-ldap~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap-debuginfo", rpm: "php5-ldap-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring", rpm: "php5-mbstring~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring-debuginfo", rpm: "php5-mbstring-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt", rpm: "php5-mcrypt~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt-debuginfo", rpm: "php5-mcrypt-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mssql", rpm: "php5-mssql~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mssql-debuginfo", rpm: "php5-mssql-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql", rpm: "php5-mysql~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql-debuginfo", rpm: "php5-mysql-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc", rpm: "php5-odbc~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc-debuginfo", rpm: "php5-odbc-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl", rpm: "php5-openssl~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl-debuginfo", rpm: "php5-openssl-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl", rpm: "php5-pcntl~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl-debuginfo", rpm: "php5-pcntl-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo", rpm: "php5-pdo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo-debuginfo", rpm: "php5-pdo-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql", rpm: "php5-pgsql~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql-debuginfo", rpm: "php5-pgsql-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-phar", rpm: "php5-phar~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-phar-debuginfo", rpm: "php5-phar-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-posix", rpm: "php5-posix~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-posix-debuginfo", rpm: "php5-posix-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell", rpm: "php5-pspell~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell-debuginfo", rpm: "php5-pspell-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-readline", rpm: "php5-readline~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-readline-debuginfo", rpm: "php5-readline-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop", rpm: "php5-shmop~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop-debuginfo", rpm: "php5-shmop-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp", rpm: "php5-snmp~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp-debuginfo", rpm: "php5-snmp-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap", rpm: "php5-soap~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap-debuginfo", rpm: "php5-soap-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sockets", rpm: "php5-sockets~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sockets-debuginfo", rpm: "php5-sockets-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sqlite", rpm: "php5-sqlite~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sqlite-debuginfo", rpm: "php5-sqlite-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin", rpm: "php5-suhosin~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin-debuginfo", rpm: "php5-suhosin-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg", rpm: "php5-sysvmsg~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg-debuginfo", rpm: "php5-sysvmsg-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem", rpm: "php5-sysvsem~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem-debuginfo", rpm: "php5-sysvsem-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm", rpm: "php5-sysvshm~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm-debuginfo", rpm: "php5-sysvshm-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tidy", rpm: "php5-tidy~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tidy-debuginfo", rpm: "php5-tidy-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer", rpm: "php5-tokenizer~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer-debuginfo", rpm: "php5-tokenizer-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx", rpm: "php5-wddx~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx-debuginfo", rpm: "php5-wddx-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader", rpm: "php5-xmlreader~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader-debuginfo", rpm: "php5-xmlreader-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc", rpm: "php5-xmlrpc~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc-debuginfo", rpm: "php5-xmlrpc-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlwriter", rpm: "php5-xmlwriter~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlwriter-debuginfo", rpm: "php5-xmlwriter-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl", rpm: "php5-xsl~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl-debuginfo", rpm: "php5-xsl-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zip", rpm: "php5-zip~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zip-debuginfo", rpm: "php5-zip-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib", rpm: "php5-zlib~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib-debuginfo", rpm: "php5-zlib-debuginfo~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pear", rpm: "php5-pear~5.3.8~4.9.2", rls: "openSUSE12.1" ) )){
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
