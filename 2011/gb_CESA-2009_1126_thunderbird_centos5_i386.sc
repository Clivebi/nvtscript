if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-June/016011.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880870" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:1126" );
	script_cve_id( "CVE-2009-1303", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1392", "CVE-2009-1833", "CVE-2009-1836", "CVE-2009-1838" );
	script_name( "CentOS Update for thunderbird CESA-2009:1126 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "thunderbird on CentOS 5" );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed HTML mail content.
  An HTML mail message containing malicious content could cause Thunderbird
  to crash or, potentially, execute arbitrary code as the user running
  Thunderbird. (CVE-2009-1392, CVE-2009-1303, CVE-2009-1305, CVE-2009-1833,
  CVE-2009-1838)

  Several flaws were found in the way malformed HTML mail content was
  processed. An HTML mail message containing malicious content could execute
  arbitrary JavaScript in the context of the mail message, possibly
  presenting misleading data to the user, or stealing sensitive information
  such as login credentials. (CVE-2009-1306, CVE-2009-1307, CVE-2009-1308,
  CVE-2009-1309)

  A flaw was found in the way Thunderbird handled error responses returned
  from proxy servers. If an attacker is able to conduct a man-in-the-middle
  attack against a Thunderbird instance that is using a proxy server, they
  may be able to steal sensitive information from the site Thunderbird is
  displaying. (CVE-2009-1836)

  Note: JavaScript support is disabled by default in Thunderbird. None of the
  above issues are exploitable unless JavaScript is enabled.

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~2.0.0.22~2.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

