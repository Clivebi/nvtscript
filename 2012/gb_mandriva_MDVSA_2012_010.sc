if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2012-01/msg00014.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831531" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-01-23 11:31:36 +0530 (Mon, 23 Jan 2012)" );
	script_cve_id( "CVE-2011-4824" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:010" );
	script_name( "Mandriva Update for cacti MDVSA-2012:010 (cacti)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cacti'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_mes5" );
	script_tag( name: "affected", value: "cacti on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Multiple vulnerabilities has been found and corrected in cacti:

  SQL injection vulnerability in auth_login.php in Cacti before 0.8.7h
  allows remote attackers to execute arbitrary SQL commands via the
  login_username parameter (CVE-2011-4824).

  Various vulnerabilities were discovered and fixed in the 0.8.7i version
  (cacti bug 2062).

  The updated packages provides the latest 0.8.7i version which are
  not affected by these issues." );
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
	if(( res = isrpmvuln( pkg: "cacti", rpm: "cacti~0.8.7i~0.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

