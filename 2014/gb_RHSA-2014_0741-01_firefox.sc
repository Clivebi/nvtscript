if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871179" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-06-17 10:07:02 +0530 (Tue, 17 Jun 2014)" );
	script_cve_id( "CVE-2014-1533", "CVE-2014-1538", "CVE-2014-1541" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "RedHat Update for firefox RHSA-2014:0741-01" );
	script_tag( name: "affected", value: "firefox on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "insight", value: "Mozilla Firefox is an open source web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2014-1533, CVE-2014-1538, CVE-2014-1541)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Gary Kwong, Christoph Diehl, Christian Holler, Hannes
Verschore, Jan de Mooij, Ryan VanderMeulen, Jeff Walden, Kyle Huey,
Abhishek Arya, and Nils as the original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Firefox 24.6.0 ESR. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 24.6.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:0741-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-June/msg00030.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(6|5)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~24.6.0~1.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "firefox-debuginfo", rpm: "firefox-debuginfo~24.6.0~1.el6_5", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~24.6.0~1.el5_10", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "firefox-debuginfo", rpm: "firefox-debuginfo~24.6.0~1.el5_10", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

