if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123407" );
	script_version( "2020-11-19T10:53:01+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:03:23 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2014-0596" );
	script_tag( name: "insight", value: "ELSA-2014-0596 - libtasn1 security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2014-0596" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2014-0596.html" );
	script_cve_id( "CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(( res = isrpmvuln( pkg: "libtasn1", rpm: "libtasn1~2.3~6.el6_5", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtasn1-devel", rpm: "libtasn1-devel~2.3~6.el6_5", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtasn1-tools", rpm: "libtasn1-tools~2.3~6.el6_5", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );

