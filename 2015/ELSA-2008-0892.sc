if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122553" );
	script_version( "2020-12-18T09:21:52+0000" );
	script_tag( name: "creation_date", value: "2015-10-08 14:47:51 +0300 (Thu, 08 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-12-18 09:21:52 +0000 (Fri, 18 Dec 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2008-0892" );
	script_tag( name: "insight", value: "ELSA-2008-0892 - xen security and bug fix update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2008-0892" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2008-0892.html" );
	script_cve_id( "CVE-2008-1945", "CVE-2008-1952" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
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
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~3.0.3~64.el5_2.3", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~3.0.3~64.el5_2.3", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~3.0.3~64.el5_2.3", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );
