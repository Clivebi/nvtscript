if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0365.1" );
	script_cve_id( "CVE-2004-1019", "CVE-2014-8142", "CVE-2014-9427", "CVE-2015-0231", "CVE-2015-0232" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:14 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:25:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0365-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0365-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150365-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php5' package(s) announced via the SUSE-SU-2015:0365-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "php5 was updated to fix four security issues.

These security issues were fixed:
- CVE-2015-0231: Use-after-free vulnerability in the process_nested_data
 function in ext/standard/var_unserializer.re in PHP before 5.4.37, 5.5.x
 before 5.5.21, and 5.6.x before 5.6.5 allowed remote attackers to
 execute arbitrary code via a crafted unserialize call that leverages
 improper handling of duplicate numerical keys within the serialized
 properties of an object. NOTE: this vulnerability exists because of an
 incomplete fix for CVE-2014-8142 (bnc#910659).
- CVE-2014-9427: sapi/cgi/cgi_main.c in the CGI component in PHP through
 5.4.36, 5.5.x through 5.5.20, and 5.6.x through 5.6.4, when mmap is used
 to read a .php file, did not properly consider the mapping's length
 during processing of an invalid file that begins with a # character and
 lacks a newline character, which caused an out-of-bounds read and might
 (1) allow remote attackers to obtain sensitive information from php-cgi
 process memory by leveraging the ability to upload a .php file or (2)
 trigger unexpected code execution if a valid PHP script is present in
 memory locations adjacent to the mapping (bnc#911664).
- CVE-2015-0232: The exif_process_unicode function in ext/exif/exif.c in
 PHP before 5.4.37, 5.5.x before 5.5.21, and 5.6.x before 5.6.5 allowed
 remote attackers to execute arbitrary code or cause a denial of service
 (uninitialized pointer free and application crash) via crafted EXIF data
 in a JPEG image (bnc#914690).
- CVE-2014-8142: Use-after-free vulnerability in the process_nested_data
 function in ext/standard/var_unserializer.re in PHP before 5.4.36, 5.5.x
 before 5.5.20, and 5.6.x before 5.6.4 allowed remote attackers to
 execute arbitrary code via a crafted unserialize call that leverages
 improper handling of duplicate keys within the serialized properties of
 an object, a different vulnerability than CVE-2004-1019 (bnc#910659).

Additionally a fix was included that protects against a possible NULL pointer use (bnc#910659).

This non-security issue was fixed:
- php53 ignored default_socket_timeout on outgoing SSL connection
 (bnc#907519)." );
	script_tag( name: "affected", value: "'php5' package(s) on SUSE Linux Enterprise Module for Web Scripting 12, SUSE Linux Enterprise Software Development Kit 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5", rpm: "apache2-mod_php5~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php5-debuginfo", rpm: "apache2-mod_php5-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5", rpm: "php5~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath", rpm: "php5-bcmath~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bcmath-debuginfo", rpm: "php5-bcmath-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2", rpm: "php5-bz2~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-bz2-debuginfo", rpm: "php5-bz2-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar", rpm: "php5-calendar~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-calendar-debuginfo", rpm: "php5-calendar-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype", rpm: "php5-ctype~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ctype-debuginfo", rpm: "php5-ctype-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl", rpm: "php5-curl~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-curl-debuginfo", rpm: "php5-curl-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba", rpm: "php5-dba~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dba-debuginfo", rpm: "php5-dba-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-debuginfo", rpm: "php5-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-debugsource", rpm: "php5-debugsource~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom", rpm: "php5-dom~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-dom-debuginfo", rpm: "php5-dom-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-enchant", rpm: "php5-enchant~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-enchant-debuginfo", rpm: "php5-enchant-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif", rpm: "php5-exif~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-exif-debuginfo", rpm: "php5-exif-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi", rpm: "php5-fastcgi~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fastcgi-debuginfo", rpm: "php5-fastcgi-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fileinfo", rpm: "php5-fileinfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fileinfo-debuginfo", rpm: "php5-fileinfo-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fpm", rpm: "php5-fpm~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-fpm-debuginfo", rpm: "php5-fpm-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp", rpm: "php5-ftp~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ftp-debuginfo", rpm: "php5-ftp-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd", rpm: "php5-gd~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gd-debuginfo", rpm: "php5-gd-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext", rpm: "php5-gettext~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gettext-debuginfo", rpm: "php5-gettext-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp", rpm: "php5-gmp~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-gmp-debuginfo", rpm: "php5-gmp-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv", rpm: "php5-iconv~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-iconv-debuginfo", rpm: "php5-iconv-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-intl", rpm: "php5-intl~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-intl-debuginfo", rpm: "php5-intl-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json", rpm: "php5-json~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-json-debuginfo", rpm: "php5-json-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap", rpm: "php5-ldap~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-ldap-debuginfo", rpm: "php5-ldap-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring", rpm: "php5-mbstring~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mbstring-debuginfo", rpm: "php5-mbstring-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt", rpm: "php5-mcrypt~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mcrypt-debuginfo", rpm: "php5-mcrypt-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql", rpm: "php5-mysql~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-mysql-debuginfo", rpm: "php5-mysql-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc", rpm: "php5-odbc~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-odbc-debuginfo", rpm: "php5-odbc-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl", rpm: "php5-openssl~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-openssl-debuginfo", rpm: "php5-openssl-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl", rpm: "php5-pcntl~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pcntl-debuginfo", rpm: "php5-pcntl-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo", rpm: "php5-pdo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pdo-debuginfo", rpm: "php5-pdo-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pear", rpm: "php5-pear~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql", rpm: "php5-pgsql~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pgsql-debuginfo", rpm: "php5-pgsql-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell", rpm: "php5-pspell~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-pspell-debuginfo", rpm: "php5-pspell-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop", rpm: "php5-shmop~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-shmop-debuginfo", rpm: "php5-shmop-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp", rpm: "php5-snmp~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-snmp-debuginfo", rpm: "php5-snmp-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap", rpm: "php5-soap~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-soap-debuginfo", rpm: "php5-soap-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sockets", rpm: "php5-sockets~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sockets-debuginfo", rpm: "php5-sockets-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sqlite", rpm: "php5-sqlite~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sqlite-debuginfo", rpm: "php5-sqlite-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin", rpm: "php5-suhosin~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-suhosin-debuginfo", rpm: "php5-suhosin-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg", rpm: "php5-sysvmsg~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvmsg-debuginfo", rpm: "php5-sysvmsg-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem", rpm: "php5-sysvsem~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvsem-debuginfo", rpm: "php5-sysvsem-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm", rpm: "php5-sysvshm~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-sysvshm-debuginfo", rpm: "php5-sysvshm-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer", rpm: "php5-tokenizer~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-tokenizer-debuginfo", rpm: "php5-tokenizer-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx", rpm: "php5-wddx~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-wddx-debuginfo", rpm: "php5-wddx-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader", rpm: "php5-xmlreader~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlreader-debuginfo", rpm: "php5-xmlreader-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc", rpm: "php5-xmlrpc~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlrpc-debuginfo", rpm: "php5-xmlrpc-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlwriter", rpm: "php5-xmlwriter~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xmlwriter-debuginfo", rpm: "php5-xmlwriter-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl", rpm: "php5-xsl~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-xsl-debuginfo", rpm: "php5-xsl-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zip", rpm: "php5-zip~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zip-debuginfo", rpm: "php5-zip-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib", rpm: "php5-zlib~5.5.14~11.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php5-zlib-debuginfo", rpm: "php5-zlib-debuginfo~5.5.14~11.3", rls: "SLES12.0" ) )){
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
