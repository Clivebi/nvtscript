if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.122035" );
	script_version( "2020-08-04T07:16:50+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:12:00 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 07:16:50 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2011-1749" );
	script_tag( name: "insight", value: "ELSA-2011-1749 - libxml2 security and bug fix update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2011-1749" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2011-1749.html" );
	script_cve_id( "CVE-2010-4008", "CVE-2010-4494", "CVE-2011-0216", "CVE-2011-1944", "CVE-2011-2821", "CVE-2011-2834" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
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
	if(( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.7.6~4.0.1.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.7.6~4.0.1.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.7.6~4.0.1.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-static", rpm: "libxml2-static~2.7.6~4.0.1.el6", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

