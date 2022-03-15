if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2012-02/msg00036.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831560" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-07 11:21:08 +0530 (Wed, 07 Mar 2012)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVA", value: "2012:024" );
	script_name( "Mandriva Update for rpm-mandriva-setup MDVA-2012:024 (rpm-mandriva-setup)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rpm-mandriva-setup'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2010\\.1" );
	script_tag( name: "affected", value: "rpm-mandriva-setup on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "Add support for partial strip for the debug info package generation." );
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
	if(( res = isrpmvuln( pkg: "rpm-mandriva-setup", rpm: "rpm-mandriva-setup~1.104~2.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rpm-mandriva-setup-build", rpm: "rpm-mandriva-setup-build~1.104~2.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

