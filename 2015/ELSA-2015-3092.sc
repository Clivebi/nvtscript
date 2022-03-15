if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122724" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-11-08 13:05:15 +0200 (Sun, 08 Nov 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-3092" );
	script_tag( name: "insight", value: "ELSA-2015-3092 - Unbreakable Enterprise kernel security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-3092" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-3092.html" );
	script_cve_id( "CVE-2015-5156" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux(7|6)" );
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
	if(( res = isrpmvuln( pkg: "dtrace-modules", rpm: "dtrace-modules~3.8.13~98.5.2.el7uek~0.4.5~3.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek", rpm: "kernel-uek~3.8.13~98.5.2.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-debug", rpm: "kernel-uek-debug~3.8.13~98.5.2.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-debug-devel", rpm: "kernel-uek-debug-devel~3.8.13~98.5.2.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-devel", rpm: "kernel-uek-devel~3.8.13~98.5.2.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-doc", rpm: "kernel-uek-doc~3.8.13~98.5.2.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-firmware", rpm: "kernel-uek-firmware~3.8.13~98.5.2.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "dtrace-modules", rpm: "dtrace-modules~3.8.13~98.5.2.el6uek~0.4.5~3.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek", rpm: "kernel-uek~3.8.13~98.5.2.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-debug", rpm: "kernel-uek-debug~3.8.13~98.5.2.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-debug-devel", rpm: "kernel-uek-debug-devel~3.8.13~98.5.2.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-devel", rpm: "kernel-uek-devel~3.8.13~98.5.2.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-doc", rpm: "kernel-uek-doc~3.8.13~98.5.2.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-firmware", rpm: "kernel-uek-firmware~3.8.13~98.5.2.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

