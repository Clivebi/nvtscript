if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881720" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-04-25 10:22:57 +0530 (Thu, 25 Apr 2013)" );
	script_cve_id( "CVE-2013-1944" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "CentOS Update for curl CESA-2013:0771 centos5" );
	script_xref( name: "CESA", value: "2013:0771" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-April/019704.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "curl on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "cURL provides the libcurl library and a command line tool for downloading
  files from servers using various protocols, including HTTP, FTP, and LDAP.

  A flaw was found in the way libcurl matched domains associated with
  cookies. This could lead to cURL or an application linked against libcurl
  sending the wrong cookie if only part of the domain name matched the domain
  associated with the cookie, disclosing the cookie to unrelated hosts.
  (CVE-2013-1944)

  Red Hat would like to thank the cURL project for reporting this issue.
  Upstream acknowledges YAMADA Yasuharu as the original reporter.

  Users of curl should upgrade to these updated packages, which contain a
  backported patch to correct this issue. All running applications using
  libcurl must be restarted for the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "curl", rpm: "curl~7.15.5~16.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "curl-devel", rpm: "curl-devel~7.15.5~16.el5_9", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

