if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-02/msg00015.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831337" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-02-28 16:24:14 +0100 (Mon, 28 Feb 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2011:033" );
	script_cve_id( "CVE-2010-4367", "CVE-2010-4369" );
	script_name( "Mandriva Update for awstats MDVSA-2011:033 (awstats)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'awstats'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_mes5" );
	script_tag( name: "affected", value: "awstats on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "Multiple vulnerabilities has been found and corrected in awstats:

  awstats.cgi in AWStats before 7.0 accepts a configdir parameter in
  the URL, which allows remote attackers to execute arbitrary commands
  via a crafted configuration file located on a (1) WebDAV server or
  (2) NFS server (CVE-2010-4367).

  Directory traversal vulnerability in AWStats before 7.0 allows remote
  attackers to have an unspecified impact via a crafted LoadPlugin
  directory (CVE-2010-4369).

  The updated packages have been upgraded to the latest version to
  address these vulnerabilities." );
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
	if(( res = isrpmvuln( pkg: "awstats", rpm: "awstats~7.0~0.1mdvmes5.1", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

