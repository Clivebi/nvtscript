if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-June/015965.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880803" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:1096" );
	script_cve_id( "CVE-2009-1392", "CVE-2009-1833", "CVE-2009-1835", "CVE-2009-1838", "CVE-2009-1841" );
	script_name( "CentOS Update for seamonkey CESA-2009:1096 centos3 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS3" );
	script_tag( name: "affected", value: "seamonkey on CentOS 3" );
	script_tag( name: "insight", value: "SeaMonkey is an open source Web browser, email and newsgroup client, IRC
  chat client, and HTML editor.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause SeaMonkey to crash or,
  potentially, execute arbitrary code as the user running SeaMonkey.
  (CVE-2009-1392, CVE-2009-1833, CVE-2009-1838, CVE-2009-1841)

  A flaw was found in the processing of malformed, local file content. If a
  user loaded malicious, local content via the file:// URL, it was possible
  for that content to access other local data. (CVE-2009-1835)

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
if(release == "CentOS3"){
	if(( res = isrpmvuln( pkg: "seamonkey", rpm: "seamonkey~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-chat", rpm: "seamonkey-chat~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-devel", rpm: "seamonkey-devel~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-dom-inspector", rpm: "seamonkey-dom-inspector~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-js-debugger", rpm: "seamonkey-js-debugger~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-mail", rpm: "seamonkey-mail~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-nspr", rpm: "seamonkey-nspr~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-nspr-devel", rpm: "seamonkey-nspr-devel~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-nss", rpm: "seamonkey-nss~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "seamonkey-nss-devel", rpm: "seamonkey-nss-devel~1.0.9~0.38.el3.centos3", rls: "CentOS3" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

