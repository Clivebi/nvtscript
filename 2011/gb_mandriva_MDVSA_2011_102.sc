if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-05/msg00028.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831411" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-03 09:20:26 +0200 (Fri, 03 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2011:102" );
	script_cve_id( "CVE-2011-1595" );
	script_name( "Mandriva Update for rdesktop MDVSA-2011:102 (rdesktop)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rdesktop'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2010\\.1|2009\\.0)" );
	script_tag( name: "affected", value: "rdesktop on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been identified and fixed in rdesktop:

  Directory traversal vulnerability in the disk_create function in
  disk.c in rdesktop before 1.7.0, when disk redirection is enabled,
  allows remote RDP servers to read or overwrite arbitrary files via
  a .. (dot dot) in a pathname (CVE-2011-1595).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages have been patched to correct this issue." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://store.mandriva.com/product_info.php\\?cPath=149\\&amp;amp;products_id=490" );
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
	if(( res = isrpmvuln( pkg: "rdesktop", rpm: "rdesktop~1.6.0~4.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "rdesktop", rpm: "rdesktop~1.6.0~11.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2009.0"){
	if(( res = isrpmvuln( pkg: "rdesktop", rpm: "rdesktop~1.6.0~4.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

