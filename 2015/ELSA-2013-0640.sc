if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123663" );
	script_version( "2020-03-13T10:06:41+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:06:57 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2013-0640" );
	script_tag( name: "insight", value: "ELSA-2013-0640 - tomcat5 security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2013-0640" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2013-0640.html" );
	script_cve_id( "CVE-2012-3546", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux5" );
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
if(release == "OracleLinux5"){
	if(( res = isrpmvuln( pkg: "tomcat5", rpm: "tomcat5~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-admin-webapps", rpm: "tomcat5-admin-webapps~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-common-lib", rpm: "tomcat5-common-lib~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jasper", rpm: "tomcat5-jasper~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jasper-javadoc", rpm: "tomcat5-jasper-javadoc~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jsp-2.0-api", rpm: "tomcat5-jsp-2.0-api~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-jsp-2.0-api-javadoc", rpm: "tomcat5-jsp-2.0-api-javadoc~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-server-lib", rpm: "tomcat5-server-lib~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-servlet-2.4-api", rpm: "tomcat5-servlet-2.4-api~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-servlet-2.4-api-javadoc", rpm: "tomcat5-servlet-2.4-api-javadoc~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tomcat5-webapps", rpm: "tomcat5-webapps~5.5.23~0jpp.38.el5_9", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

