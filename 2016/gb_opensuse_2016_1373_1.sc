if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851319" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-05-21 05:21:12 +0200 (Sat, 21 May 2016)" );
	script_cve_id( "CVE-2015-8866", "CVE-2015-8867", "CVE-2016-4070", "CVE-2016-4071", "CVE-2016-4073" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for php5 (openSUSE-SU-2016:1373-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php5'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for php5 fixes the following security issues:

  - CVE-2016-4073: A remote attacker could have caused denial of service, or
  possibly execute arbitrary code, due to incorrect handling of string
  length calculations in mb_strcut() (bsc#977003)

  - CVE-2015-8867: The PHP function openssl_random_pseudo_bytes() did not
  return cryptographically secure random bytes (bsc#977005)

  - CVE-2016-4070: The libxml_disable_entity_loader() setting was shared
  between threads, which could have resulted in XML external entity
  injection and entity expansion issues (bsc#976997)

  - CVE-2015-8866: A remote attacker could have caused denial of service due
  to incorrect handling of large strings in php_raw_url_encode()
  (bsc#976996)

  - CVE-2016-4071: A remote attacker could have caused denial of service, or
  possibly execute arbitrary code, due to incorrect handling of string
  formatting in php_snmp_error() (bsc#977000)

  This update was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "php5 on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1373-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5", rpm: "apache2-mod_php5~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5-debuginfo", rpm: "apache2-mod_php5-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5", rpm: "php5~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath", rpm: "php5-bcmath~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath-debuginfo", rpm: "php5-bcmath-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2", rpm: "php5-bz2~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2-debuginfo", rpm: "php5-bz2-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar", rpm: "php5-calendar~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar-debuginfo", rpm: "php5-calendar-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype", rpm: "php5-ctype~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype-debuginfo", rpm: "php5-ctype-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl", rpm: "php5-curl~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl-debuginfo", rpm: "php5-curl-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba", rpm: "php5-dba~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba-debuginfo", rpm: "php5-dba-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-debuginfo", rpm: "php5-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-debugsource", rpm: "php5-debugsource~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-devel", rpm: "php5-devel~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom", rpm: "php5-dom~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom-debuginfo", rpm: "php5-dom-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-enchant", rpm: "php5-enchant~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-enchant-debuginfo", rpm: "php5-enchant-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif", rpm: "php5-exif~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif-debuginfo", rpm: "php5-exif-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi", rpm: "php5-fastcgi~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi-debuginfo", rpm: "php5-fastcgi-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fileinfo", rpm: "php5-fileinfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fileinfo-debuginfo", rpm: "php5-fileinfo-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-firebird", rpm: "php5-firebird~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-firebird-debuginfo", rpm: "php5-firebird-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fpm", rpm: "php5-fpm~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fpm-debuginfo", rpm: "php5-fpm-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp", rpm: "php5-ftp~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp-debuginfo", rpm: "php5-ftp-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd", rpm: "php5-gd~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd-debuginfo", rpm: "php5-gd-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext", rpm: "php5-gettext~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext-debuginfo", rpm: "php5-gettext-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp", rpm: "php5-gmp~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp-debuginfo", rpm: "php5-gmp-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv", rpm: "php5-iconv~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv-debuginfo", rpm: "php5-iconv-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-imap", rpm: "php5-imap~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-imap-debuginfo", rpm: "php5-imap-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-intl", rpm: "php5-intl~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-intl-debuginfo", rpm: "php5-intl-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json", rpm: "php5-json~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json-debuginfo", rpm: "php5-json-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap", rpm: "php5-ldap~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap-debuginfo", rpm: "php5-ldap-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring", rpm: "php5-mbstring~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring-debuginfo", rpm: "php5-mbstring-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt", rpm: "php5-mcrypt~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt-debuginfo", rpm: "php5-mcrypt-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mssql", rpm: "php5-mssql~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mssql-debuginfo", rpm: "php5-mssql-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql", rpm: "php5-mysql~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql-debuginfo", rpm: "php5-mysql-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc", rpm: "php5-odbc~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc-debuginfo", rpm: "php5-odbc-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-opcache", rpm: "php5-opcache~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-opcache-debuginfo", rpm: "php5-opcache-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl", rpm: "php5-openssl~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl-debuginfo", rpm: "php5-openssl-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl", rpm: "php5-pcntl~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl-debuginfo", rpm: "php5-pcntl-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo", rpm: "php5-pdo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo-debuginfo", rpm: "php5-pdo-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql", rpm: "php5-pgsql~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql-debuginfo", rpm: "php5-pgsql-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-phar", rpm: "php5-phar~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-phar-debuginfo", rpm: "php5-phar-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-posix", rpm: "php5-posix~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-posix-debuginfo", rpm: "php5-posix-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell", rpm: "php5-pspell~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell-debuginfo", rpm: "php5-pspell-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-readline", rpm: "php5-readline~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-readline-debuginfo", rpm: "php5-readline-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop", rpm: "php5-shmop~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop-debuginfo", rpm: "php5-shmop-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp", rpm: "php5-snmp~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp-debuginfo", rpm: "php5-snmp-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap", rpm: "php5-soap~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap-debuginfo", rpm: "php5-soap-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sockets", rpm: "php5-sockets~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sockets-debuginfo", rpm: "php5-sockets-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sqlite", rpm: "php5-sqlite~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sqlite-debuginfo", rpm: "php5-sqlite-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin", rpm: "php5-suhosin~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin-debuginfo", rpm: "php5-suhosin-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg", rpm: "php5-sysvmsg~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg-debuginfo", rpm: "php5-sysvmsg-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem", rpm: "php5-sysvsem~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem-debuginfo", rpm: "php5-sysvsem-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm", rpm: "php5-sysvshm~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm-debuginfo", rpm: "php5-sysvshm-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tidy", rpm: "php5-tidy~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tidy-debuginfo", rpm: "php5-tidy-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer", rpm: "php5-tokenizer~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer-debuginfo", rpm: "php5-tokenizer-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx", rpm: "php5-wddx~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx-debuginfo", rpm: "php5-wddx-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader", rpm: "php5-xmlreader~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader-debuginfo", rpm: "php5-xmlreader-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc", rpm: "php5-xmlrpc~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc-debuginfo", rpm: "php5-xmlrpc-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlwriter", rpm: "php5-xmlwriter~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlwriter-debuginfo", rpm: "php5-xmlwriter-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl", rpm: "php5-xsl~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl-debuginfo", rpm: "php5-xsl-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zip", rpm: "php5-zip~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zip-debuginfo", rpm: "php5-zip-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib", rpm: "php5-zlib~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib-debuginfo", rpm: "php5-zlib-debuginfo~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pear", rpm: "php5-pear~5.5.14~47.1", rls: "openSUSELeap42.1" ) )){
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
