if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.880498" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2010:0981" );
	script_cve_id( "CVE-2010-2997", "CVE-2010-4375", "CVE-2010-4378", "CVE-2010-4379", "CVE-2010-4382", "CVE-2010-4383", "CVE-2010-4384", "CVE-2010-4385", "CVE-2010-4386", "CVE-2010-4392" );
	script_name( "CentOS Update for HelixPlayer-uninstall CESA-2010:0981 centos4 i386" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-January/017237.html" );
	script_xref( name: "URL", value: "https://player.helixcommunity.org" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'HelixPlayer-uninstall'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "HelixPlayer-uninstall on CentOS 4" );
	script_tag( name: "insight", value: "Helix Player is a media player.

  Multiple security flaws were discovered in RealPlayer. Helix Player and
  RealPlayer share a common source code base. Therefore, some of the flaws
  discovered in RealPlayer may also affect Helix Player. Some of these flaws
  could, when opening, viewing, or playing a malicious media file or stream,
  lead to arbitrary code execution with the privileges of the user running
  Helix Player. (CVE-2010-2997, CVE-2010-4375, CVE-2010-4378, CVE-2010-4379,
  CVE-2010-4382, CVE-2010-4383, CVE-2010-4384, CVE-2010-4385, CVE-2010-4386,
  CVE-2010-4392)

  The Red Hat Security Response Team is unable to properly determine the
  impact or fix all of these issues in Helix Player, due to the source code
  for RealPlayer being unavailable.

  Due to the security concerns this update removes the HelixPlayer package
  from Red Hat Enterprise Linux 4. Users wishing to continue to use Helix
  Player should download it directly from the linked references." );
	script_tag( name: "solution", value: "Please install the updated packages." );
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
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "HelixPlayer-uninstall", rpm: "HelixPlayer-uninstall~1.0.6~3.el4_8.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "HelixPlayer", rpm: "HelixPlayer~1.0.6~3.el4_8.1", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

