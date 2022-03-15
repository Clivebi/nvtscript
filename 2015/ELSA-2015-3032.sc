if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123124" );
	script_version( "2020-05-26T08:07:04+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 09:48:11 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-05-26 08:07:04 +0000 (Tue, 26 May 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-3032" );
	script_tag( name: "insight", value: "ELSA-2015-3032 - Unbreakable Enterprise kernel security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-3032" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-3032.html" );
	script_cve_id( "CVE-2014-3215", "CVE-2014-8171", "CVE-2014-9529", "CVE-2014-9584" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
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
	if(( res = isrpmvuln( pkg: "dtrace-modules", rpm: "dtrace-modules~3.8.13~68.1.3.el7uek~0.4.3~4.el7", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek", rpm: "kernel-uek~3.8.13~68.1.3.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-debug", rpm: "kernel-uek-debug~3.8.13~68.1.3.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-debug-devel", rpm: "kernel-uek-debug-devel~3.8.13~68.1.3.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-devel", rpm: "kernel-uek-devel~3.8.13~68.1.3.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-doc", rpm: "kernel-uek-doc~3.8.13~68.1.3.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-firmware", rpm: "kernel-uek-firmware~3.8.13~68.1.3.el7uek", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "dtrace-modules", rpm: "dtrace-modules~3.8.13~68.1.3.el6uek~0.4.3~4.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek", rpm: "kernel-uek~3.8.13~68.1.3.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-debug", rpm: "kernel-uek-debug~3.8.13~68.1.3.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-debug-devel", rpm: "kernel-uek-debug-devel~3.8.13~68.1.3.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-devel", rpm: "kernel-uek-devel~3.8.13~68.1.3.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-doc", rpm: "kernel-uek-doc~3.8.13~68.1.3.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-uek-firmware", rpm: "kernel-uek-firmware~3.8.13~68.1.3.el6uek", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

