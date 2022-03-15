if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-01/msg00007.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831303" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-01-14 16:07:43 +0100 (Fri, 14 Jan 2011)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVA", value: "2011:001" );
	script_name( "Mandriva Update for openoffice.org-voikko MDVA-2011:001 (openoffice.org-voikko)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openoffice.org-voikko'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2010\\.1" );
	script_tag( name: "affected", value: "openoffice.org-voikko on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "The previous advisory MDVA-2011:000 updated openoffice.org to 3.2.1
  but didn't include a rebuilt openoffice.org-voikko, thus preventing
  installation of the update when the openoffice.org Finnish language
  package is installed.

  This advisory fixes the issue by providing the missing packages." );
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
	if(( res = isrpmvuln( pkg: "openoffice.org-voikko", rpm: "openoffice.org-voikko~3.1~4.3mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

