if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2011-March/msg00009.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870404" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "RHSA", value: "2011:0313-01" );
	script_cve_id( "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0059" );
	script_name( "RedHat Update for seamonkey RHSA-2011:0313-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_4" );
	script_tag( name: "affected", value: "seamonkey on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "SeaMonkey is an open source web browser, email and newsgroup client, IRC
  chat client, and HTML editor.

  A flaw was found in the way SeaMonkey handled dialog boxes. An attacker
  could use this flaw to create a malicious web page that would present a
  blank dialog box that has non-functioning buttons. If a user closes the
  dialog box window, it could unexpectedly grant the malicious web page
  elevated privileges. (CVE-2011-0051)

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause SeaMonkey to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  SeaMonkey. (CVE-2011-0053)

  A flaw was found in the way SeaMonkey handled plug-ins that perform HTTP
  requests. If a plug-in performed an HTTP request, and the server sent a 307
  redirect response, the plug-in was not notified, and the HTTP request was
  forwarded. The forwarded request could contain custom headers, which could
  result in a Cross Site Request Forgery attack. (CVE-2011-0059)

  All SeaMonkey users should upgrade to these updated packages, which correct
  these issues. After installing the update, SeaMonkey must be restarted for
  the changes to take effect." );
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
if(release == "RHENT_4"){
	if(( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~1.0.9~67.el4_8", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-chat", rpm: "seamonkey-chat~1.0.9~67.el4_8", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-debuginfo", rpm: "seamonkey-debuginfo~1.0.9~67.el4_8", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-devel", rpm: "seamonkey-devel~1.0.9~67.el4_8", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-dom-inspector", rpm: "seamonkey-dom-inspector~1.0.9~67.el4_8", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-js-debugger", rpm: "seamonkey-js-debugger~1.0.9~67.el4_8", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-mail", rpm: "seamonkey-mail~1.0.9~67.el4_8", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

