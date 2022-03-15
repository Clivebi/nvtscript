if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122871" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-02-05 14:01:40 +0200 (Fri, 05 Feb 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-1186" );
	script_tag( name: "insight", value: "ELSA-2015-1186 - php55-php security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-1186" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-1186.html" );
	script_cve_id( "CVE-2015-4643", "CVE-2015-4644", "CVE-2015-2783", "CVE-2015-3307", "CVE-2015-3329", "CVE-2015-3330", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026", "CVE-2015-4598", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
	script_family( "Oracle Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "OracleLinux7"){
	if(( res = isrpmvuln( pkg: "php55-php", rpm: "php55-php~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-bcmath", rpm: "php55-php-bcmath~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-cli", rpm: "php55-php-cli~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-common", rpm: "php55-php-common~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-dba", rpm: "php55-php-dba~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-devel", rpm: "php55-php-devel~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-enchant", rpm: "php55-php-enchant~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-fpm", rpm: "php55-php-fpm~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-gd", rpm: "php55-php-gd~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-gmp", rpm: "php55-php-gmp~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-intl", rpm: "php55-php-intl~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-ldap", rpm: "php55-php-ldap~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-mbstring", rpm: "php55-php-mbstring~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-mysqlnd", rpm: "php55-php-mysqlnd~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-odbc", rpm: "php55-php-odbc~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-opcache", rpm: "php55-php-opcache~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-pdo", rpm: "php55-php-pdo~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-pgsql", rpm: "php55-php-pgsql~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-process", rpm: "php55-php-process~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-pspell", rpm: "php55-php-pspell~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-recode", rpm: "php55-php-recode~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-snmp", rpm: "php55-php-snmp~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-soap", rpm: "php55-php-soap~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-xml", rpm: "php55-php-xml~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php55-php-xmlrpc", rpm: "php55-php-xmlrpc~5.5.21~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

