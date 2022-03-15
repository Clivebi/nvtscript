if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-02/msg00017.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831340" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "MDVSA", value: "2011:035" );
	script_cve_id( "CVE-2005-4790", "CVE-2010-4005" );
	script_name( "Mandriva Update for tomboy MDVSA-2011:035 (tomboy)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomboy'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2010\\.1|2010\\.0)" );
	script_tag( name: "affected", value: "tomboy on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in tomboy:

  The (1) tomboy and (2) tomboy-panel scripts in GNOME Tomboy 1.5.2 and
  earlier place a zero-length directory name in the LD_LIBRARY_PATH,
  which allows local users to gain privileges via a Trojan horse shared
  library in the current working directory.  NOTE: vector 1 exists
  because of an incorrect fix for CVE-2005-4790.2 (CVE-2010-4005).

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
	if(( res = isrpmvuln( pkg: "tomboy", rpm: "tomboy~1.2.2~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.0"){
	if(( res = isrpmvuln( pkg: "tomboy", rpm: "tomboy~1.0.0~1.1mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

