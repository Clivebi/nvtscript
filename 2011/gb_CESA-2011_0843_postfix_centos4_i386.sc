if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-June/017605.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880488" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-06 16:56:27 +0200 (Mon, 06 Jun 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:0843" );
	script_cve_id( "CVE-2011-1720" );
	script_name( "CentOS Update for postfix CESA-2011:0843 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postfix'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "postfix on CentOS 4" );
	script_tag( name: "insight", value: "Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
  and TLS.

  A heap-based buffer over-read flaw was found in the way Postfix performed
  SASL handlers management for SMTP sessions, when Cyrus SASL authentication
  was enabled. A remote attacker could use this flaw to cause the Postfix
  smtpd server to crash via a specially-crafted SASL authentication request.
  The smtpd process was automatically restarted by the postfix master process
  after the time configured with service_throttle_time elapsed.
  (CVE-2011-1720)

  Note: Cyrus SASL authentication for Postfix is not enabled by default.

  Red Hat would like to thank the CERT/CC for reporting this issue. Upstream
  acknowledges Thomas Jarosch of Intra2net AG as the original reporter.

  Users of Postfix are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, the postfix service will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "postfix", rpm: "postfix~2.2.10~1.5.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "postfix-pflogsumm", rpm: "postfix-pflogsumm~2.2.10~1.5.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

