if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-03/msg00008.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831351" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-24 14:29:52 +0100 (Thu, 24 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "MDVSA", value: "2011:049" );
	script_cve_id( "CVE-2010-2632", "CVE-2011-0762" );
	script_name( "Mandriva Update for vsftpd MDVSA-2011:049 (vsftpd)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vsftpd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2010\\.1|2010\\.0|2009\\.0)" );
	script_tag( name: "affected", value: "vsftpd on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "A vulnerability was discovered and corrected in vsftpd:

  The vsf_filename_passes_filter function in ls.c in vsftpd before 2.3.3
  allows remote authenticated users to cause a denial of service (CPU
  consumption and process slot exhaustion) via crafted glob expressions
  in STAT commands in multiple FTP sessions, a different vulnerability
  than CVE-2010-2632 (CVE-2011-0762).

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
	if(( res = isrpmvuln( pkg: "vsftpd", rpm: "vsftpd~2.2.2~4.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.0"){
	if(( res = isrpmvuln( pkg: "vsftpd", rpm: "vsftpd~2.1.2~2.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2009.0"){
	if(( res = isrpmvuln( pkg: "vsftpd", rpm: "vsftpd~2.0.7~1.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

