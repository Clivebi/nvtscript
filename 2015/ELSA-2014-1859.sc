if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123248" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:01:15 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2014-1859" );
	script_tag( name: "insight", value: "ELSA-2014-1859 - mysql55-mysql security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2014-1859" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2014-1859.html" );
	script_cve_id( "CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6484", "CVE-2014-6505", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6559", "CVE-2014-6551", "CVE-2014-4287", "CVE-2014-6469", "CVE-2014-6507", "CVE-2014-6555" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
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
	if(( res = isrpmvuln( pkg: "mysql55-mysql", rpm: "mysql55-mysql~5.5.40~2.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql55-mysql-bench", rpm: "mysql55-mysql-bench~5.5.40~2.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql55-mysql-devel", rpm: "mysql55-mysql-devel~5.5.40~2.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql55-mysql-libs", rpm: "mysql55-mysql-libs~5.5.40~2.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql55-mysql-server", rpm: "mysql55-mysql-server~5.5.40~2.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mysql55-mysql-test", rpm: "mysql55-mysql-test~5.5.40~2.el5", rls: "OracleLinux5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );
