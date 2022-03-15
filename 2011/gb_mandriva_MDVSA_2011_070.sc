if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-04/msg00014.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831370" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-04-11 15:05:25 +0200 (Mon, 11 Apr 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "MDVSA", value: "2011:070" );
	script_cve_id( "CVE-2011-0727" );
	script_name( "Mandriva Update for gdm MDVSA-2011:070 (gdm)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdm'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2010\\.1" );
	script_tag( name: "affected", value: "gdm on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in gdm:

  GNOME Display Manager (gdm) 2.x before 2.32.1 allows local users to
  change the ownership of arbitrary files via a symlink attack on a
  (1) dmrc or (2) face icon file under /var/cache/gdm/ (CVE-2011-0727).

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
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "gdm", rpm: "gdm~2.30.2~12.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gdm-user-switch-applet", rpm: "gdm-user-switch-applet~2.30.2~12.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

