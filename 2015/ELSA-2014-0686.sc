if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123374" );
	script_version( "2020-03-13T10:06:41+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:02:57 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2014-0686" );
	script_tag( name: "insight", value: "ELSA-2014-0686 - tomcat security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2014-0686" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2014-0686.html" );
	script_cve_id( "CVE-2013-4286", "CVE-2013-4322", "CVE-2014-0186" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux7" );
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
if(release == "OracleLinux7"){
	if(( res = isrpmvuln( pkg: "tomcat", rpm: "tomcat~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-admin-webapps", rpm: "tomcat-admin-webapps~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-docs-webapp", rpm: "tomcat-docs-webapp~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-el-2.2-api", rpm: "tomcat-el-2.2-api~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-javadoc", rpm: "tomcat-javadoc~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-jsp-2.2-api", rpm: "tomcat-jsp-2.2-api~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-jsvc", rpm: "tomcat-jsvc~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-lib", rpm: "tomcat-lib~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-servlet-3.0-api", rpm: "tomcat-servlet-3.0-api~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat-webapps", rpm: "tomcat-webapps~7.0.42~5.el7_0", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

