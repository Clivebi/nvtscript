if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122915" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-03-31 08:06:17 +0300 (Thu, 31 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2016-0512" );
	script_tag( name: "insight", value: "ELSA-2016-0512 - java-1.7.0-openjdk security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2016-0512" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2016-0512.html" );
	script_cve_id( "CVE-2016-0636" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux(7|5)" );
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
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.99~2.6.5.0.0.1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-accessibility", rpm: "java-1.7.0-openjdk-accessibility~1.7.0.99~2.6.5.0.0.1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-demo", rpm: "java-1.7.0-openjdk-demo~1.7.0.99~2.6.5.0.0.1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-devel", rpm: "java-1.7.0-openjdk-devel~1.7.0.99~2.6.5.0.0.1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-headless", rpm: "java-1.7.0-openjdk-headless~1.7.0.99~2.6.5.0.0.1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-javadoc", rpm: "java-1.7.0-openjdk-javadoc~1.7.0.99~2.6.5.0.0.1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-src", rpm: "java-1.7.0-openjdk-src~1.7.0.99~2.6.5.0.0.1.el7_2", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(release == "OracleLinux5"){
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.99~2.6.5.0.0.1.el5_11", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-demo", rpm: "java-1.7.0-openjdk-demo~1.7.0.99~2.6.5.0.0.1.el5_11", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-devel", rpm: "java-1.7.0-openjdk-devel~1.7.0.99~2.6.5.0.0.1.el5_11", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-javadoc", rpm: "java-1.7.0-openjdk-javadoc~1.7.0.99~2.6.5.0.0.1.el5_11", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.7.0-openjdk-src", rpm: "java-1.7.0-openjdk-src~1.7.0.99~2.6.5.0.0.1.el5_11", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

