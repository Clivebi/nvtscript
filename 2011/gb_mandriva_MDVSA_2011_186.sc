if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-12/msg00008.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831505" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-12-16 11:12:38 +0530 (Fri, 16 Dec 2011)" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2011:186" );
	script_cve_id( "CVE-2011-1749" );
	script_name( "Mandriva Update for nfs-utils MDVSA-2011:186 (nfs-utils)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nfs-utils'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2010\\.1)" );
	script_tag( name: "affected", value: "nfs-utils on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been discovered and corrected in nfs-utils
  It was found that the mount.nfs tool did not handle certain errors
  correctly when updating the mtab (mounted file systems table)
  file. A local attacker could use this flaw to corrupt the mtab file
  (CVE-2011-1749).

  The updated packages have been patched to correct this issue." );
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
	if(( res = isrpmvuln( pkg: "nfs-utils", rpm: "nfs-utils~1.1.3~10.3mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nfs-utils-clients", rpm: "nfs-utils-clients~1.1.3~10.3mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "nfs-utils", rpm: "nfs-utils~1.2.2~5.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nfs-utils-clients", rpm: "nfs-utils-clients~1.2.2~5.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

