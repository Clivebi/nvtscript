if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-08/msg00004.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831437" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "MDVSA", value: "2011:122" );
	script_cve_id( "CVE-2011-2721" );
	script_name( "Mandriva Update for clamav MDVSA-2011:122 (clamav)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2009\\.0)" );
	script_tag( name: "affected", value: "clamav on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been discovered and corrected in clamav:

  Off-by-one error in the cli_hm_scan function in matcher-hash.c in
  libclamav in ClamAV before 0.97.2 allows remote attackers to cause
  a denial of service (daemon crash) via an e-mail message that is not
  properly handled during certain hash calculations (CVE-2011-2721).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages have been upgraded to the 0.97.2 version which
  is not vulnerable to this issue." );
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
if(release == "MNDK_mes5"){
	if(( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.97.2~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "clamav-db", rpm: "clamav-db~0.97.2~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "clamav-milter", rpm: "clamav-milter~0.97.2~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "clamd", rpm: "clamd~0.97.2~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libclamav6", rpm: "libclamav6~0.97.2~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libclamav-devel", rpm: "libclamav-devel~0.97.2~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64clamav6", rpm: "lib64clamav6~0.97.2~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64clamav-devel", rpm: "lib64clamav-devel~0.97.2~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2009.0"){
	if(( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.97.2~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "clamav-db", rpm: "clamav-db~0.97.2~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "clamav-milter", rpm: "clamav-milter~0.97.2~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "clamd", rpm: "clamd~0.97.2~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libclamav6", rpm: "libclamav6~0.97.2~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libclamav-devel", rpm: "libclamav-devel~0.97.2~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64clamav6", rpm: "lib64clamav6~0.97.2~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64clamav-devel", rpm: "lib64clamav-devel~0.97.2~0.1mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

