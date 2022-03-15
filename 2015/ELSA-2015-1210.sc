if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123084" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 13:59:10 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-1210" );
	script_tag( name: "insight", value: "ELSA-2015-1210 -  abrt security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-1210" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-1210.html" );
	script_cve_id( "CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3147", "CVE-2015-3159", "CVE-2015-3315" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
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
	if(( res = isrpmvuln( pkg: "abrt", rpm: "abrt~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-addon-ccpp", rpm: "abrt-addon-ccpp~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-addon-kerneloops", rpm: "abrt-addon-kerneloops~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-addon-python", rpm: "abrt-addon-python~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-addon-vmcore", rpm: "abrt-addon-vmcore~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-cli", rpm: "abrt-cli~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-console-notification", rpm: "abrt-console-notification~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-desktop", rpm: "abrt-desktop~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-devel", rpm: "abrt-devel~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-gui", rpm: "abrt-gui~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-libs", rpm: "abrt-libs~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-python", rpm: "abrt-python~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "abrt-tui", rpm: "abrt-tui~2.0.8~26.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport", rpm: "libreport~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-cli", rpm: "libreport-cli~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-compat", rpm: "libreport-compat~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-devel", rpm: "libreport-devel~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-filesystem", rpm: "libreport-filesystem~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-gtk", rpm: "libreport-gtk~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-gtk-devel", rpm: "libreport-gtk-devel~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-newt", rpm: "libreport-newt~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-plugin-bugzilla", rpm: "libreport-plugin-bugzilla~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-plugin-kerneloops", rpm: "libreport-plugin-kerneloops~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-plugin-logger", rpm: "libreport-plugin-logger~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-plugin-mailx", rpm: "libreport-plugin-mailx~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-plugin-reportuploader", rpm: "libreport-plugin-reportuploader~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libreport-python", rpm: "libreport-python~2.0.9~21.0.1.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

