if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-January/018372.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881119" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:13:47 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-4566", "CVE-2011-4885" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_xref( name: "CESA", value: "2012:0019" );
	script_name( "CentOS Update for php53 CESA-2012:0019 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php53'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "php53 on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Server.

  It was found that the hashing routine used by PHP arrays was susceptible
  to predictable hash collisions. If an HTTP POST request to a PHP
  application contained many parameters whose names map to the same hash
  value, a large amount of CPU time would be consumed. This flaw has been
  mitigated by adding a new configuration directive, max_input_vars, that
  limits the maximum number of parameters processed per request. By
  default, max_input_vars is set to 1000. (CVE-2011-4885)

  An integer overflow flaw was found in the PHP exif extension. On 32-bit
  systems, a specially-crafted image file could cause the PHP interpreter to
  crash or disclose portions of its memory when a PHP script tries to extract
  Exchangeable image file format (Exif) metadata from the image file.
  (CVE-2011-4566)

  Red Hat would like to thank oCERT for reporting CVE-2011-4885. oCERT
  acknowledges Julian Wlde and Alexander Klink as the original reporters of
  CVE-2011-4885.

  All php53 and php users should upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing the
  updated packages, the httpd daemon must be restarted for the update to take
  effect." );
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
	if(( res = isrpmvuln( pkg: "php53", rpm: "php53~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-bcmath", rpm: "php53-bcmath~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-cli", rpm: "php53-cli~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-common", rpm: "php53-common~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-dba", rpm: "php53-dba~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-devel", rpm: "php53-devel~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-gd", rpm: "php53-gd~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-imap", rpm: "php53-imap~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-intl", rpm: "php53-intl~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-ldap", rpm: "php53-ldap~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-mbstring", rpm: "php53-mbstring~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-mysql", rpm: "php53-mysql~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-odbc", rpm: "php53-odbc~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-pdo", rpm: "php53-pdo~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-pgsql", rpm: "php53-pgsql~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-process", rpm: "php53-process~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-pspell", rpm: "php53-pspell~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-snmp", rpm: "php53-snmp~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-soap", rpm: "php53-soap~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-xml", rpm: "php53-xml~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "php53-xmlrpc", rpm: "php53-xmlrpc~5.3.3~1.el5_7.5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

