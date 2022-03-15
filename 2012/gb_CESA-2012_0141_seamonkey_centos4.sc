if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-February/018442.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881126" );
	script_version( "2020-04-21T06:28:23+0000" );
	script_tag( name: "last_modification", value: "2020-04-21 06:28:23 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-07-30 16:16:36 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-3026" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:0141" );
	script_name( "CentOS Update for seamonkey CESA-2012:0141 centos4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "seamonkey on CentOS 4" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "SeaMonkey is an open source web browser, e-mail and newsgroup client, IRC
  chat client, and HTML editor.

  A heap-based buffer overflow flaw was found in the way SeaMonkey handled
  PNG (Portable Network Graphics) images. A web page containing a malicious
  PNG image could cause SeaMonkey to crash or, possibly, execute arbitrary
  code with the privileges of the user running SeaMonkey. (CVE-2011-3026)

  All SeaMonkey users should upgrade to these updated packages, which correct
  this issue. After installing the update, SeaMonkey must be restarted for
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
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~1.0.9~79.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-chat", rpm: "seamonkey-chat~1.0.9~79.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-devel", rpm: "seamonkey-devel~1.0.9~79.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-dom-inspector", rpm: "seamonkey-dom-inspector~1.0.9~79.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-js-debugger", rpm: "seamonkey-js-debugger~1.0.9~79.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-mail", rpm: "seamonkey-mail~1.0.9~79.el4.centos", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

