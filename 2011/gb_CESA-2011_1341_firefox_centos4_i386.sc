if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-September/018085.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881014" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-09-30 16:02:57 +0200 (Fri, 30 Sep 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2011:1341" );
	script_cve_id( "CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000" );
	script_name( "CentOS Update for firefox CESA-2011:1341 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "firefox on CentOS 4" );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-2995)

  A flaw was found in the way Firefox processed the 'Enter' keypress event. A
  malicious web page could present a download dialog while the key is
  pressed, activating the default 'Open' action. A remote attacker could
  exploit this vulnerability by causing the browser to open malicious web
  content. (CVE-2011-2372)

  A flaw was found in the way Firefox handled Location headers in redirect
  responses. Two copies of this header with different values could be a
  symptom of a CRLF injection attack against a vulnerable server. Firefox now
  treats two copies of the Location, Content-Length, or Content-Disposition
  header as an error condition. (CVE-2011-3000)

  A flaw was found in the way Firefox handled frame objects with certain
  names. An attacker could use this flaw to cause a plug-in to grant its
  content access to another site or the local file system, violating the
  same-origin policy. (CVE-2011-2999)

  An integer underflow flaw was found in the way Firefox handled large
  JavaScript regular expressions. A web page containing malicious JavaScript
  could cause Firefox to access already freed memory, causing Firefox to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running Firefox. (CVE-2011-2998)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.23. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.6.23, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect." );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~3.6.23~1.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

