if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-08/msg00001.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831434" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-12 15:49:01 +0200 (Fri, 12 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "MDVA", value: "2011:027" );
	script_name( "Mandriva Update for bind MDVA-2011:027 (bind)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2010\\.1|2009\\.0)" );
	script_tag( name: "affected", value: "bind on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "This is maintenance release that upgrades ISC BIND to the 9.7.4
  version that addresses a lot of upstream bugs and fixes." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
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
if(release == "MNDK_mes5"){
	if(( res = isrpmvuln( pkg: "bind", rpm: "bind~9.7.4~0.0.0.1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.7.4~0.0.0.1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.7.4~0.0.0.1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.7.4~0.0.0.1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "bind", rpm: "bind~9.7.4~0.0.0.1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.7.4~0.0.0.1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.7.4~0.0.0.1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.7.4~0.0.0.1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2009.0"){
	if(( res = isrpmvuln( pkg: "bind", rpm: "bind~9.7.4~0.0.0.1.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.7.4~0.0.0.1.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-doc", rpm: "bind-doc~9.7.4~0.0.0.1.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.7.4~0.0.0.1.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
