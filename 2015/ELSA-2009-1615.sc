if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122416" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-08 14:44:54 +0300 (Thu, 08 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2009-1615" );
	script_tag( name: "insight", value: "ELSA-2009-1615 - xerces-j2 security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2009-1615" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2009-1615.html" );
	script_cve_id( "CVE-2009-2625" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
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
	if(( res = isrpmvuln( pkg: "xerces-j2", rpm: "xerces-j2~2.7.1~7jpp.2.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-demo", rpm: "xerces-j2-demo~2.7.1~7jpp.2.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-javadoc-apis", rpm: "xerces-j2-javadoc-apis~2.7.1~7jpp.2.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-javadoc-impl", rpm: "xerces-j2-javadoc-impl~2.7.1~7jpp.2.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-javadoc-other", rpm: "xerces-j2-javadoc-other~2.7.1~7jpp.2.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-javadoc-xni", rpm: "xerces-j2-javadoc-xni~2.7.1~7jpp.2.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xerces-j2-scripts", rpm: "xerces-j2-scripts~2.7.1~7jpp.2.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

