if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:002" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831520" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-01-09 13:30:29 +0530 (Mon, 09 Jan 2012)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:002" );
	script_cve_id( "CVE-2011-0764" );
	script_name( "Mandriva Update for t1lib MDVSA-2012:002 (t1lib)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 't1lib'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2011\\.0|mes5\\.2|2010\\.1)" );
	script_tag( name: "affected", value: "t1lib on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2,
  Mandriva Linux 2010.1" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in t1lib:

  t1lib 5.1.2 and earlier uses an invalid pointer in conjunction with
  a dereference operation, which allows remote attackers to execute
  arbitrary code via a specially crafted Type 1 font in a PDF document
  (CVE-2011-0764).

  The updated packages have been patched to correct this issue." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_2011.0"){
	if(( res = isrpmvuln( pkg: "libt1lib5", rpm: "libt1lib5~5.1.2~11.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libt1lib-devel", rpm: "libt1lib-devel~5.1.2~11.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libt1lib-static-devel", rpm: "libt1lib-static-devel~5.1.2~11.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-config", rpm: "t1lib-config~5.1.2~11.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-progs", rpm: "t1lib-progs~5.1.2~11.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib5", rpm: "lib64t1lib5~5.1.2~11.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib-devel", rpm: "lib64t1lib-devel~5.1.2~11.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib-static-devel", rpm: "lib64t1lib-static-devel~5.1.2~11.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_mes5.2"){
	if(( res = isrpmvuln( pkg: "libt1lib5", rpm: "libt1lib5~5.1.2~4.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libt1lib-devel", rpm: "libt1lib-devel~5.1.2~4.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libt1lib-static-devel", rpm: "libt1lib-static-devel~5.1.2~4.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-config", rpm: "t1lib-config~5.1.2~4.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-progs", rpm: "t1lib-progs~5.1.2~4.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib5", rpm: "lib64t1lib5~5.1.2~4.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib-devel", rpm: "lib64t1lib-devel~5.1.2~4.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib-static-devel", rpm: "lib64t1lib-static-devel~5.1.2~4.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "libt1lib5", rpm: "libt1lib5~5.1.2~8.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libt1lib-devel", rpm: "libt1lib-devel~5.1.2~8.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libt1lib-static-devel", rpm: "libt1lib-static-devel~5.1.2~8.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-config", rpm: "t1lib-config~5.1.2~8.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-progs", rpm: "t1lib-progs~5.1.2~8.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib5", rpm: "lib64t1lib5~5.1.2~8.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib-devel", rpm: "lib64t1lib-devel~5.1.2~8.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64t1lib-static-devel", rpm: "lib64t1lib-static-devel~5.1.2~8.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

