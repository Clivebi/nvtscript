if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122728" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-11-08 13:05:18 +0200 (Sun, 08 Nov 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-1978" );
	script_tag( name: "insight", value: "ELSA-2015-1978 - kernel security, bug fix, and enhancement update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-1978" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-1978.html" );
	script_cve_id( "CVE-2014-8559", "CVE-2015-5156" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
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
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-abi-whitelists", rpm: "kernel-abi-whitelists~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf", rpm: "perf~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~3.10.0~229.20.1.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );
