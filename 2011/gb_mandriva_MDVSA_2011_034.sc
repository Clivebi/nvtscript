if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-02/msg00016.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831338" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "MDVSA", value: "2011:034" );
	script_cve_id( "CVE-2010-3998" );
	script_name( "Mandriva Update for banshee MDVSA-2011:034 (banshee)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'banshee'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2010\\.1|2010\\.0|2009\\.0)" );
	script_tag( name: "affected", value: "banshee on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in banshee:

  The (1) banshee-1 and (2) muinshee scripts in Banshee 1.8.0 and
  earlier place a zero-length directory name in the LD_LIBRARY_PATH,
  which allows local users to gain privileges via a Trojan horse shared
  library in the current working directory (CVE-2010-3998).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages have been patched to correct this issue." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://store.mandriva.com/product_info.php?cPath=149&amp;amp;products_id=490" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "banshee", rpm: "banshee~1.6.0~6.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-doc", rpm: "banshee-doc~1.6.0~6.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-ipod", rpm: "banshee-ipod~1.6.0~6.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-karma", rpm: "banshee-karma~1.6.0~6.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-mtp", rpm: "banshee-mtp~1.6.0~6.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.0"){
	if(( res = isrpmvuln( pkg: "banshee", rpm: "banshee~1.5.1~2.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-doc", rpm: "banshee-doc~1.5.1~2.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-ipod", rpm: "banshee-ipod~1.5.1~2.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-karma", rpm: "banshee-karma~1.5.1~2.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-mtp", rpm: "banshee-mtp~1.5.1~2.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2009.0"){
	if(( res = isrpmvuln( pkg: "banshee", rpm: "banshee~1.2.1~6.2mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-doc", rpm: "banshee-doc~1.2.1~6.2mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-ipod", rpm: "banshee-ipod~1.2.1~6.2mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "banshee-mtp", rpm: "banshee-mtp~1.2.1~6.2mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

