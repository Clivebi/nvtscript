if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123999" );
	script_version( "2020-09-01T08:56:50+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:11:29 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-09-01 08:56:50 +0000 (Tue, 01 Sep 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2012-0080" );
	script_tag( name: "insight", value: "ELSA-2012-0080 - thunderbird security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2012-0080" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2012-0080.html" );
	script_cve_id( "CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0449" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~3.1.18~1.0.1.el6_2", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

