if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122814" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_tag( name: "creation_date", value: "2016-01-08 07:47:19 +0200 (Fri, 08 Jan 2016)" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_name( "Oracle Linux Local Check: ELSA-2016-0011" );
	script_tag( name: "insight", value: "ELSA-2016-0011 - samba security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2016-0011" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2016-0011.html" );
	script_cve_id( "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-31 02:59:00 +0000 (Sat, 31 Dec 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libsmbclient-devel", rpm: "libsmbclient-devel~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba", rpm: "samba~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-domainjoin-gui", rpm: "samba-domainjoin-gui~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-swat", rpm: "samba-swat~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-clients", rpm: "samba-winbind-clients~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-devel", rpm: "samba-winbind-devel~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-winbind-krb5-locator", rpm: "samba-winbind-krb5-locator~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-glusterfs", rpm: "samba-glusterfs~3.6.23~24.0.1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

