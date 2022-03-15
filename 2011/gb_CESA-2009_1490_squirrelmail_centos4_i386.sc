if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-October/016185.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880918" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:1490" );
	script_cve_id( "CVE-2009-2964" );
	script_name( "CentOS Update for squirrelmail CESA-2009:1490 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squirrelmail'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "squirrelmail on CentOS 4" );
	script_tag( name: "insight", value: "SquirrelMail is a standards-based webmail package written in PHP.

  Form submissions in SquirrelMail did not implement protection against
  Cross-Site Request Forgery (CSRF) attacks. If a remote attacker tricked a
  user into visiting a malicious web page, the attacker could hijack that
  user's authentication, inject malicious content into that user's
  preferences, or possibly send mail without that user's permission.
  (CVE-2009-2964)

  Users of SquirrelMail should upgrade to this updated package, which
  contains a backported patch to correct these issues." );
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
	if(( res = isrpmvuln( pkg: "squirrelmail", rpm: "squirrelmail~1.4.8~5.el4_8.8", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

