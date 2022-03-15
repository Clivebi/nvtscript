if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-May/017556.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881329" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:25:09 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-0419" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0507" );
	script_name( "CentOS Update for apr CESA-2011:0507 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apr'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "apr on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The Apache Portable Runtime (APR) is a portability library used by the
  Apache HTTP Server and other projects. It provides a free library of C data
  structures and routines.

  It was discovered that the apr_fnmatch() function used an unconstrained
  recursion when processing patterns with the '*' wildcard. An attacker could
  use this flaw to cause an application using this function, which also
  accepted untrusted input as a pattern for matching (such as an httpd server
  using the mod_autoindex module), to exhaust all stack memory or use an
  excessive amount of CPU time when performing matching. (CVE-2011-0419)

  Red Hat would like to thank Maksymilian Arciemowicz for reporting this
  issue.

  All apr users should upgrade to these updated packages, which contain a
  backported patch to correct this issue. Applications using the apr library,
  such as httpd, must be restarted for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "apr", rpm: "apr~1.2.7~11.el5_6.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "apr-devel", rpm: "apr-devel~1.2.7~11.el5_6.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "apr-docs", rpm: "apr-docs~1.2.7~11.el5_6.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

