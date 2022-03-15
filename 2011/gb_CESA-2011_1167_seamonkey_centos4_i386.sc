if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-August/017694.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880963" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2011:1167" );
	script_cve_id( "CVE-2011-2982", "CVE-2011-2983" );
	script_name( "CentOS Update for seamonkey CESA-2011:1167 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "seamonkey on CentOS 4" );
	script_tag( name: "insight", value: "SeaMonkey is an open source web browser, email and newsgroup client, IRC
  chat client, and HTML editor.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause SeaMonkey to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  SeaMonkey. (CVE-2011-2982)

  A flaw was found in the way SeaMonkey handled malformed JavaScript. A web
  page containing malicious JavaScript could cause SeaMonkey to access
  already freed memory, causing SeaMonkey to crash or, potentially, execute
  arbitrary code with the privileges of the user running SeaMonkey.
  (CVE-2011-2983)

  All SeaMonkey users should upgrade to these updated packages, which correct
  these issues. After installing the update, SeaMonkey must be restarted for
  the changes to take effect." );
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
	if(( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~1.0.9~72.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-chat", rpm: "seamonkey-chat~1.0.9~72.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-devel", rpm: "seamonkey-devel~1.0.9~72.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-dom-inspector", rpm: "seamonkey-dom-inspector~1.0.9~72.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-js-debugger", rpm: "seamonkey-js-debugger~1.0.9~72.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-mail", rpm: "seamonkey-mail~1.0.9~72.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

