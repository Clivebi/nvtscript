if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122422" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-08 14:45:01 +0300 (Thu, 08 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2009-1548" );
	script_tag( name: "insight", value: "ELSA-2009-1548 - kernel security and bug fix update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2009-1548" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2009-1548.html" );
	script_cve_id( "CVE-2009-2695", "CVE-2009-2908", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3613" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
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
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE", rpm: "kernel-PAE~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE-devel", rpm: "kernel-PAE-devel~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~2.6.18~164.6.1.0.1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ocfs2", rpm: "ocfs2~2.6.18~164.6.1.0.1.el5~1.4.4~1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ocfs2", rpm: "ocfs2~2.6.18~164.6.1.0.1.el5PAE~1.4.4~1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ocfs2", rpm: "ocfs2~2.6.18~164.6.1.0.1.el5debug~1.4.4~1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ocfs2", rpm: "ocfs2~2.6.18~164.6.1.0.1.el5xen~1.4.4~1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "oracleasm", rpm: "oracleasm~2.6.18~164.6.1.0.1.el5~2.0.5~1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "oracleasm", rpm: "oracleasm~2.6.18~164.6.1.0.1.el5PAE~2.0.5~1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "oracleasm", rpm: "oracleasm~2.6.18~164.6.1.0.1.el5debug~2.0.5~1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "oracleasm", rpm: "oracleasm~2.6.18~164.6.1.0.1.el5xen~2.0.5~1.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

