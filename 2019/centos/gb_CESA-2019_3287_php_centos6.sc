if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883128" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_cve_id( "CVE-2019-11043" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-02 03:00:45 +0000 (Sat, 02 Nov 2019)" );
	script_name( "CentOS Update for php CESA-2019:3287 centos6 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2019:3287" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-November/023506.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php'
  package(s) announced via the CESA-2019:3287 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "PHP is an HTML-embedded scripting language commonly used with the Apache
HTTP Server.

Security Fix(es):

  * php: underflow in env_path_info in fpm_main.c (CVE-2019-11043)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'php' package(s) on CentOS 6." );
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
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "php", rpm: "php~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-bcmath", rpm: "php-bcmath~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-cli", rpm: "php-cli~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-common", rpm: "php-common~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-dba", rpm: "php-dba~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-devel", rpm: "php-devel~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-embedded", rpm: "php-embedded~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-enchant", rpm: "php-enchant~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-fpm", rpm: "php-fpm~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-gd", rpm: "php-gd~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-imap", rpm: "php-imap~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-intl", rpm: "php-intl~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ldap", rpm: "php-ldap~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-mbstring", rpm: "php-mbstring~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-mysql", rpm: "php-mysql~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-odbc", rpm: "php-odbc~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-pdo", rpm: "php-pdo~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-pgsql", rpm: "php-pgsql~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-process", rpm: "php-process~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-pspell", rpm: "php-pspell~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-recode", rpm: "php-recode~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-snmp", rpm: "php-snmp~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-soap", rpm: "php-soap~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-tidy", rpm: "php-tidy~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-xml", rpm: "php-xml~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-xmlrpc", rpm: "php-xmlrpc~5.3.3~50.el6_10", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-zts", rpm: "php-zts~5.3.3~50.el6_10", rls: "CentOS6" ) )){
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

