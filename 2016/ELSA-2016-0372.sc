if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122898" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2016-03-11 07:06:41 +0200 (Fri, 11 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2016-0372" );
	script_tag( name: "insight", value: "ELSA-2016-0372 - openssl098e security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2016-0372" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2016-0372.html" );
	script_cve_id( "CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0800", "CVE-2016-0703", "CVE-2016-0704" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/oracle_linux", "ssh/login/release",  "ssh/login/release=OracleLinux(7|6)" );
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
if(release == "OracleLinux7"){
	if(( res = isrpmvuln( pkg: "openssl098e", rpm: "openssl098e~0.9.8e~29.el7_2.3", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "openssl098e", rpm: "openssl098e~0.9.8e~20.0.1.el6_7.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

