if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-May/015945.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880772" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:1066" );
	script_cve_id( "CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1581" );
	script_name( "CentOS Update for squirrelmail CESA-2009:1066 centos3 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squirrelmail'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS3" );
	script_tag( name: "affected", value: "squirrelmail on CentOS 3" );
	script_tag( name: "insight", value: "SquirrelMail is a standards-based webmail package written in PHP.

  A server-side code injection flaw was found in the SquirrelMail
  'map_yp_alias' function. If SquirrelMail was configured to retrieve a
  user's IMAP server address from a Network Information Service (NIS) server
  via the 'map_yp_alias' function, an unauthenticated, remote attacker using
  a specially-crafted username could use this flaw to execute arbitrary code
  with the privileges of the web server. (CVE-2009-1579)

  Multiple cross-site scripting (XSS) flaws were found in SquirrelMail. An
  attacker could construct a carefully crafted URL, which once visited by an
  unsuspecting user, could cause the user's web browser to execute malicious
  script in the context of the visited SquirrelMail web page. (CVE-2009-1578)

  It was discovered that SquirrelMail did not properly sanitize Cascading
  Style Sheets (CSS) directives used in HTML mail. A remote attacker could
  send a specially-crafted email that could place mail content above
  SquirrelMail's controls, possibly allowing phishing and cross-site
  scripting attacks. (CVE-2009-1581)

  Users of squirrelmail should upgrade to this updated package, which
  contains backported patches to correct these issues." );
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
if(release == "CentOS3"){
	if(( res = isrpmvuln( pkg: "squirrelmail", rpm: "squirrelmail~1.4.8~13.el3.centos.1", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

