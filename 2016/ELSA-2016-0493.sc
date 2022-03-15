if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122908" );
	script_version( "2021-02-05T10:24:35+0000" );
	script_tag( name: "creation_date", value: "2016-03-23 07:08:56 +0200 (Wed, 23 Mar 2016)" );
	script_tag( name: "last_modification", value: "2021-02-05 10:24:35 +0000 (Fri, 05 Feb 2021)" );
	script_name( "Oracle Linux Local Check: ELSA-2016-0493" );
	script_tag( name: "insight", value: "ELSA-2016-0493 - krb5 security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2016-0493" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2016-0493.html" );
	script_cve_id( "CVE-2015-8629", "CVE-2015-8631" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
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
	if(( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.10.3~42z1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-libs", rpm: "krb5-libs~1.10.3~42z1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-pkinit-openssl", rpm: "krb5-pkinit-openssl~1.10.3~42z1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.10.3~42z1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server-ldap", rpm: "krb5-server-ldap~1.10.3~42z1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-workstation", rpm: "krb5-workstation~1.10.3~42z1.el6_7", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

