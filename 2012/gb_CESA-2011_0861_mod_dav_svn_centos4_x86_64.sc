if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-August/017676.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881275" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:15:14 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-1752" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0861" );
	script_name( "CentOS Update for mod_dav_svn CESA-2011:0861 centos4 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mod_dav_svn'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "mod_dav_svn on CentOS 4" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Subversion (SVN) is a concurrent version control system which enables one
  or more users to collaborate in developing and maintaining a hierarchy of
  files and directories while keeping a history of all changes. The
  mod_dav_svn module is used with the Apache HTTP Server to allow access to
  Subversion repositories via HTTP.

  A NULL pointer dereference flaw was found in the way the mod_dav_svn module
  processed requests submitted against the URL of a baselined resource. A
  malicious, remote user could use this flaw to cause the httpd process
  serving the request to crash. (CVE-2011-1752)

  Red Hat would like to thank the Apache Subversion project for reporting
  this issue. Upstream acknowledges Joe Schaefer of the Apache Software
  Foundation as the original reporter.

  All Subversion users should upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  updated packages, you must restart the httpd daemon, if you are using
  mod_dav_svn, for the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "mod_dav_svn", rpm: "mod_dav_svn~1.1.4~4.el4_8", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "subversion", rpm: "subversion~1.1.4~4.el4_8", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "subversion-devel", rpm: "subversion-devel~1.1.4~4.el4_8", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "subversion-perl", rpm: "subversion-perl~1.1.4~4.el4_8", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

