if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-05/msg00026.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831406" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-03 09:20:26 +0200 (Fri, 03 Jun 2011)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVA", value: "2011:023" );
	script_name( "Mandriva Update for mkinitrd MDVA-2011:023 (mkinitrd)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mkinitrd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_mes5" );
	script_tag( name: "affected", value: "mkinitrd on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "mkinirtd needs the cmp command from the diffutils package. This
  package is a requires for msec package, but if msec is not installed,
  mkinitrd won't work. Add a requires on diffutils." );
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
	if(( res = isrpmvuln( pkg: "libbdevid-python", rpm: "libbdevid-python~6.0.63~1.2mnb2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mkinitrd", rpm: "mkinitrd~6.0.63~1.2mnb2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mkinitrd-devel", rpm: "mkinitrd-devel~6.0.63~1.2mnb2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nash", rpm: "nash~6.0.63~1.2mnb2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

