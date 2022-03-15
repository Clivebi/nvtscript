if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123083" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 13:59:09 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-1218" );
	script_tag( name: "insight", value: "ELSA-2015-1218 - php security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-1218" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-1218.html" );
	script_cve_id( "CVE-2014-9705", "CVE-2014-9709", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-2301", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3307", "CVE-2015-3329", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2014-9425" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
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
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "php", rpm: "php~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-bcmath", rpm: "php-bcmath~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-cli", rpm: "php-cli~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-common", rpm: "php-common~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-dba", rpm: "php-dba~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-devel", rpm: "php-devel~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-embedded", rpm: "php-embedded~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-enchant", rpm: "php-enchant~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-fpm", rpm: "php-fpm~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-gd", rpm: "php-gd~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-imap", rpm: "php-imap~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-intl", rpm: "php-intl~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-ldap", rpm: "php-ldap~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-mbstring", rpm: "php-mbstring~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-mysql", rpm: "php-mysql~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-odbc", rpm: "php-odbc~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-pdo", rpm: "php-pdo~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-pgsql", rpm: "php-pgsql~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-process", rpm: "php-process~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-pspell", rpm: "php-pspell~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-recode", rpm: "php-recode~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-snmp", rpm: "php-snmp~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-soap", rpm: "php-soap~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-tidy", rpm: "php-tidy~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-xml", rpm: "php-xml~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-xmlrpc", rpm: "php-xmlrpc~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-zts", rpm: "php-zts~5.3.3~46.el6_6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

