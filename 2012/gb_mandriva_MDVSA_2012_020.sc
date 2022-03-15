if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2012-02/msg00022.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831542" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-21 19:00:53 +0530 (Tue, 21 Feb 2012)" );
	script_cve_id( "CVE-2012-0834" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "MDVSA", value: "2012:020" );
	script_name( "Mandriva Update for phpldapadmin MDVSA-2012:020 (phpldapadmin)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpldapadmin'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_mes5" );
	script_tag( name: "affected", value: "phpldapadmin on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in phpldapadmin:

  Cross-site scripting (XSS) vulnerability in lib/QueryRender.php in
  phpLDAPadmin 1.2.2 and earlier allows remote attackers to inject
  arbitrary web script or HTML via the base parameter in a query_engine
  action to cmd.php (CVE-2012-0834).

  The updated packages have been patched to correct this issue." );
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
	if(( res = isrpmvuln( pkg: "phpldapadmin", rpm: "phpldapadmin~1.2.2~0.3mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

