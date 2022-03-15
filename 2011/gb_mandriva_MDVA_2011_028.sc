if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-08/msg00002.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831435" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-12 15:49:01 +0200 (Fri, 12 Aug 2011)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
	script_xref( name: "MDVA", value: "2011:028" );
	script_name( "Mandriva Update for mmc-wizard MDVA-2011:028 (mmc-wizard)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mmc-wizard'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_mes5" );
	script_tag( name: "affected", value: "mmc-wizard on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "mmc-wizard-1.0-13.13mdvmes5.2.noarch.rpm fixes the following issues:

  - handle /usr/lib64/mmc or /usr/lib/mmc paths to the mmc scripts

  - the package postfix-ldap is installed for the mail module" );
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
	if(( res = isrpmvuln( pkg: "mmc-wizard", rpm: "mmc-wizard~1.0~13.14mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

