if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-October/018126.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881020" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_xref( name: "CESA", value: "2011:1392" );
	script_cve_id( "CVE-2011-3368", "CVE-2011-3192" );
	script_name( "CentOS Update for httpd CESA-2011:1392 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "httpd on CentOS 5" );
	script_tag( name: "insight", value: "The Apache HTTP Server is a popular web server.

  It was discovered that the Apache HTTP Server did not properly validate the
  request URI for proxied requests. In certain configurations, if a reverse
  proxy used the ProxyPassMatch directive, or if it used the RewriteRule
  directive with the proxy flag, a remote attacker could make the proxy
  connect to an arbitrary server, possibly disclosing sensitive information
  from internal web servers not directly accessible to the attacker.
  (CVE-2011-3368)

  Red Hat would like to thank Context Information Security for reporting this
  issue.

  This update also fixes the following bug:

  * The fix for CVE-2011-3192 provided by the RHSA-2011:1245 update
  introduced regressions in the way httpd handled certain Range HTTP header
  values. This update corrects those regressions. (BZ#736593, BZ#736594)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "httpd", rpm: "httpd~2.2.3~53.el5.centos.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-devel", rpm: "httpd-devel~2.2.3~53.el5.centos.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-manual", rpm: "httpd-manual~2.2.3~53.el5.centos.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mod_ssl", rpm: "mod_ssl~2.2.3~53.el5.centos.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

