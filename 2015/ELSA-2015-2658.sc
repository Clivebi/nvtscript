if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122810" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-12-18 07:26:18 +0200 (Fri, 18 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-2658" );
	script_tag( name: "insight", value: "ELSA-2015-2658 - bind97 security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-2658" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-2658.html" );
	script_cve_id( "CVE-2015-8000" );
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
	if(( res = isrpmvuln( pkg: "bind97", rpm: "bind97~9.7.0~21.P2.el5_11.4", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-chroot", rpm: "bind97-chroot~9.7.0~21.P2.el5_11.4", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-devel", rpm: "bind97-devel~9.7.0~21.P2.el5_11.4", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-libs", rpm: "bind97-libs~9.7.0~21.P2.el5_11.4", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-utils", rpm: "bind97-utils~9.7.0~21.P2.el5_11.4", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

