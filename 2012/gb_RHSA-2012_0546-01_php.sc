if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2012-May/msg00004.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870593" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-05-08 12:35:43 +0530 (Tue, 08 May 2012)" );
	script_cve_id( "CVE-2012-1823" );
	script_xref( name: "RHSA", value: "2012:0546-01" );
	script_name( "RedHat Update for php RHSA-2012:0546-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	script_tag( name: "affected", value: "php on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Server.

  A flaw was found in the way the php-cgi executable processed command line
  arguments when running in CGI mode. A remote attacker could send a
  specially-crafted request to a PHP script that would result in the query
  string being parsed by php-cgi as command line options and arguments. This
  could lead to the disclosure of the script's source code or arbitrary code
  execution with the privileges of the PHP interpreter. (CVE-2012-1823)

  Red Hat is aware that a public exploit for this issue is available that
  allows remote code execution in affected PHP CGI configurations. This flaw
  does not affect the default configuration in Red Hat Enterprise Linux 5 and
  6 using the PHP module for Apache httpd to handle PHP scripts.

  All php users should upgrade to these updated packages, which contain a
  backported patch to resolve this issue. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect." );
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
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "php", rpm: "php~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-bcmath", rpm: "php-bcmath~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-cli", rpm: "php-cli~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-common", rpm: "php-common~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-dba", rpm: "php-dba~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-debuginfo", rpm: "php-debuginfo~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-devel", rpm: "php-devel~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-gd", rpm: "php-gd~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-imap", rpm: "php-imap~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-ldap", rpm: "php-ldap~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-mbstring", rpm: "php-mbstring~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-mysql", rpm: "php-mysql~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-ncurses", rpm: "php-ncurses~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-odbc", rpm: "php-odbc~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-pdo", rpm: "php-pdo~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-pgsql", rpm: "php-pgsql~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-snmp", rpm: "php-snmp~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-soap", rpm: "php-soap~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-xml", rpm: "php-xml~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php-xmlrpc", rpm: "php-xmlrpc~5.1.6~34.el5_8", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

