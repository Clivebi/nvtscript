if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0064.1" );
	script_cve_id( "CVE-2013-4248", "CVE-2013-6420", "CVE-2013-6712" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0064-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0064-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140064-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'PHP5' package(s) announced via the SUSE-SU-2014:0064-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes the following issues:

 * memory corruption in openssl_parse_x509
(CVE-2013-6420)
 * Heap buffer over-read in DateInterval (CVE-2013-6712)
 * man-in-the-middle attacks by specially crafting certificates (CVE-2013-4248)

Security Issue references:

 * CVE-2013-6420
>
 * CVE-2013-6712
>
 * CVE-2013-4248
>" );
	script_tag( name: "affected", value: "'PHP5' package(s) on SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "apache2-mod_php53", rpm: "apache2-mod_php53~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53", rpm: "php53~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-bcmath", rpm: "php53-bcmath~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-bz2", rpm: "php53-bz2~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-calendar", rpm: "php53-calendar~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-ctype", rpm: "php53-ctype~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-curl", rpm: "php53-curl~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-dba", rpm: "php53-dba~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-dom", rpm: "php53-dom~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-exif", rpm: "php53-exif~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-fastcgi", rpm: "php53-fastcgi~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-fileinfo", rpm: "php53-fileinfo~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-ftp", rpm: "php53-ftp~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-gd", rpm: "php53-gd~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-gettext", rpm: "php53-gettext~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-gmp", rpm: "php53-gmp~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-iconv", rpm: "php53-iconv~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-intl", rpm: "php53-intl~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-json", rpm: "php53-json~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-ldap", rpm: "php53-ldap~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-mbstring", rpm: "php53-mbstring~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-mcrypt", rpm: "php53-mcrypt~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-mysql", rpm: "php53-mysql~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-odbc", rpm: "php53-odbc~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-openssl", rpm: "php53-openssl~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-pcntl", rpm: "php53-pcntl~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-pdo", rpm: "php53-pdo~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-pear", rpm: "php53-pear~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-pgsql", rpm: "php53-pgsql~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-pspell", rpm: "php53-pspell~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-shmop", rpm: "php53-shmop~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-snmp", rpm: "php53-snmp~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-soap", rpm: "php53-soap~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-suhosin", rpm: "php53-suhosin~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-sysvmsg", rpm: "php53-sysvmsg~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-sysvsem", rpm: "php53-sysvsem~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-sysvshm", rpm: "php53-sysvshm~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-tokenizer", rpm: "php53-tokenizer~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-wddx", rpm: "php53-wddx~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-xmlreader", rpm: "php53-xmlreader~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-xmlrpc", rpm: "php53-xmlrpc~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-xmlwriter", rpm: "php53-xmlwriter~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-xsl", rpm: "php53-xsl~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-zip", rpm: "php53-zip~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php53-zlib", rpm: "php53-zlib~5.3.8~0.43.1", rls: "SLES11.0SP2" ) )){
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

