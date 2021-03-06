if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882542" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-13 05:51:54 +0200 (Sat, 13 Aug 2016)" );
	script_cve_id( "CVE-2016-5385" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for php CESA-2016:1613 centos7" );
	script_tag( name: "summary", value: "Check the version of php" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PHP is an HTML-embedded scripting language
commonly used with the Apache HTTP Server.

Security Fix(es):

  * It was discovered that PHP did not properly protect against the
HTTP_PROXY variable name clash. A remote attacker could possibly use this
flaw to redirect HTTP requests performed by a PHP script to an
attacker-controlled proxy via a malicious HTTP request. (CVE-2016-5385)

Red Hat would like to thank Scott Geary (VendHQ) for reporting this issue.

Bug Fix(es):

  * Previously, an incorrect logic in the SAPI header callback routine caused
that the callback counter was not incremented. Consequently, when a script
included a header callback, it could terminate unexpectedly with a
segmentation fault. With this update, the callback counter is properly
managed, and scripts with a header callback implementation work as
expected. (BZ#1346758)" );
	script_tag( name: "affected", value: "php on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1613" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-August/022036.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "php", rpm: "php~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-bcmath", rpm: "php-bcmath~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-cli", rpm: "php-cli~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-common", rpm: "php-common~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-dba", rpm: "php-dba~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-devel", rpm: "php-devel~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-embedded", rpm: "php-embedded~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-enchant", rpm: "php-enchant~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-fpm", rpm: "php-fpm~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-gd", rpm: "php-gd~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-intl", rpm: "php-intl~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-ldap", rpm: "php-ldap~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-mbstring", rpm: "php-mbstring~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-mysql", rpm: "php-mysql~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-mysqlnd", rpm: "php-mysqlnd~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-odbc", rpm: "php-odbc~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-pdo", rpm: "php-pdo~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-pgsql", rpm: "php-pgsql~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-process", rpm: "php-process~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-pspell", rpm: "php-pspell~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-recode", rpm: "php-recode~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-snmp", rpm: "php-snmp~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-soap", rpm: "php-soap~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-xml", rpm: "php-xml~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-xmlrpc", rpm: "php-xmlrpc~5.4.16~36.3.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

