if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.123157" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-06 14:00:04 +0300 (Tue, 06 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Oracle Linux Local Check: ELSA-2015-0696" );
	script_tag( name: "insight", value: "ELSA-2015-0696 - freetype security update. Please see the references for more insight." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Oracle Linux Local Security Checks ELSA-2015-0696" );
	script_xref( name: "URL", value: "http://linux.oracle.com/errata/ELSA-2015-0696.html" );
	script_cve_id( "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(( res = isrpmvuln( pkg: "freetype", rpm: "freetype~2.4.11~10.el7_1.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-demos", rpm: "freetype-demos~2.4.11~10.el7_1.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-devel", rpm: "freetype-devel~2.4.11~10.el7_1.1", rls: "OracleLinux7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(release == "OracleLinux6"){
	if(( res = isrpmvuln( pkg: "freetype", rpm: "freetype~2.3.11~15.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-demos", rpm: "freetype-demos~2.3.11~15.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "freetype-devel", rpm: "freetype-devel~2.3.11~15.el6_6.1", rls: "OracleLinux6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
}
if(__pkg_match){
	exit( 99 );
}
exit( 0 );
