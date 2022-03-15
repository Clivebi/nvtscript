if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122420" );
	script_version( "2020-10-16T08:56:40+0000" );
	script_tag( name: "creation_date", value: "2015-10-08 14:44:57 +0300 (Thu, 08 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-10-16 08:56:40 +0000 (Fri, 16 Oct 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2009-1579" );
	script_tag( name: "insight", value: "ELSA-2009-1579 - httpd security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2009-1579" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2009-1579.html" );
	script_cve_id( "CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
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
	if(( res = isrpmvuln( pkg: "httpd", rpm: "httpd~2.2.3~31.0.1.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-devel", rpm: "httpd-devel~2.2.3~31.0.1.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-manual", rpm: "httpd-manual~2.2.3~31.0.1.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mod_ssl", rpm: "mod_ssl~2.2.3~31.0.1.el5_4.2", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

