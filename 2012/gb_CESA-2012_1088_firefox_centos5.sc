if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-July/018744.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881187" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:37:11 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967", "CVE-2011-3389", "CVE-2012-1949" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2012:1088" );
	script_name( "CentOS Update for firefox CESA-2012:1088 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "firefox on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  A web page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2012-1948, CVE-2012-1951, CVE-2012-1952, CVE-2012-1953,
  CVE-2012-1954, CVE-2012-1958, CVE-2012-1962, CVE-2012-1967)

  A malicious web page could bypass same-compartment security wrappers (SCSW)
  and execute arbitrary code with chrome privileges. (CVE-2012-1959)

  A flaw in the context menu functionality in Firefox could allow a malicious
  website to bypass intended restrictions and allow a cross-site scripting
  attack. (CVE-2012-1966)

  A page different to that in the address bar could be displayed when
  dragging and dropping to the address bar, possibly making it easier for a
  malicious site or user to perform a phishing attack. (CVE-2012-1950)

  A flaw in the way Firefox called history.forward and history.back could
  allow an attacker to conceal a malicious URL, possibly tricking a user
  into believing they are viewing a trusted site. (CVE-2012-1955)

  A flaw in a parser utility class used by Firefox to parse feeds (such as
  RSS) could allow an attacker to execute arbitrary JavaScript with the
  privileges of the user running Firefox. This issue could have affected
  other browser components or add-ons that assume the class returns
  sanitized input. (CVE-2012-1957)

  A flaw in the way Firefox handled X-Frame-Options headers could allow a
  malicious website to perform a clickjacking attack. (CVE-2012-1961)

  A flaw in the way Content Security Policy (CSP) reports were generated by
  Firefox could allow a malicious web page to steal a victim's OAuth 2.0
  access tokens and OpenID credentials. (CVE-2012-1963)

  A flaw in the way Firefox handled certificate warnings could allow a
  man-in-the-middle attacker to create a crafted warning, possibly tricking
  a user into accepting an arbitrary certificate as trusted. (CVE-2012-1964)

  A flaw in the way Firefox handled feed:javascript URLs could allow output
  filtering to be bypassed, possibly leading to a cross-site scripting
  attack. (CVE-2012-1965)

  The nss update RHBA-2012:0337 for Red Hat Enterprise Linux 5 and 6
  introduced a mitigation for the CVE-2011-3389 flaw. For compatibility
  reasons, it remains disabled by default in the nss packages. This update
  makes Firefox enable the mitigation by default. It can be disabled by
  setting the NSS_SSL_CBC_RANDOM_IV environment variable to 0 before
  launching Firefox. ( ...

  Description truncated, please see the referenced URL(s) for more information." );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~10.0.6~1.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xulrunner", rpm: "xulrunner~10.0.6~2.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xulrunner-devel", rpm: "xulrunner-devel~10.0.6~2.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

