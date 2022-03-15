if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122783" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-11-25 13:18:50 +0200 (Wed, 25 Nov 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-2233" );
	script_tag( name: "insight", value: "ELSA-2015-2233 - tigervnc security, bug fix, and enhancement update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-2233" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-2233.html" );
	script_cve_id( "CVE-2014-8240", "CVE-2014-8241" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(( res = isrpmvuln( pkg: "tigervnc", rpm: "tigervnc~1.3.1~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-icons", rpm: "tigervnc-icons~1.3.1~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-license", rpm: "tigervnc-license~1.3.1~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-server", rpm: "tigervnc-server~1.3.1~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-server-applet", rpm: "tigervnc-server-applet~1.3.1~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-server-minimal", rpm: "tigervnc-server-minimal~1.3.1~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tigervnc-server-module", rpm: "tigervnc-server-module~1.3.1~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

