if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-November/018187.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881043" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-11 09:54:56 +0530 (Fri, 11 Nov 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2011:1437" );
	script_cve_id( "CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650" );
	script_name( "CentOS Update for firefox CESA-2011:1437 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "firefox on CentOS 5" );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  A flaw was found in the way Firefox handled certain add-ons. A web page
  containing malicious content could cause an add-on to grant itself full
  browser privileges, which could lead to arbitrary code execution with the
  privileges of the user running Firefox. (CVE-2011-3647)

  A cross-site scripting (XSS) flaw was found in the way Firefox handled
  certain multibyte character sets. A web page containing malicious content
  could cause Firefox to run JavaScript code with the permissions of a
  different website. (CVE-2011-3648)

  A flaw was found in the way Firefox handled large JavaScript scripts. A web
  page containing malicious JavaScript could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-3650)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.6.24. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.6.24, which corrects these issues. After installing the
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~3.6.24~3.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xulrunner", rpm: "xulrunner~1.9.2.24~2.el5_7", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xulrunner-devel", rpm: "xulrunner-devel~1.9.2.24~2.el5_7", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

