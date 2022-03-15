if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122792" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-12-02 11:24:54 +0200 (Wed, 02 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-2521" );
	script_tag( name: "insight", value: "ELSA-2015-2521 - jakarta-commons-collections security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-2521" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-2521.html" );
	script_cve_id( "CVE-2015-7501" );
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
	if(( res = isrpmvuln( pkg: "jakarta-commons-collections", rpm: "jakarta-commons-collections~3.2.1~3.5.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "jakarta-commons-collections-javadoc", rpm: "jakarta-commons-collections-javadoc~3.2.1~3.5.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "jakarta-commons-collections-testframework", rpm: "jakarta-commons-collections-testframework~3.2.1~3.5.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "jakarta-commons-collections-testframework-javadoc", rpm: "jakarta-commons-collections-testframework-javadoc~3.2.1~3.5.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "jakarta-commons-collections-tomcat5", rpm: "jakarta-commons-collections-tomcat5~3.2.1~3.5.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

