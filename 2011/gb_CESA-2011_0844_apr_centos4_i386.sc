if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-June/017607.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880490" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-06-06 16:56:27 +0200 (Mon, 06 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0844" );
	script_cve_id( "CVE-2011-1928", "CVE-2011-0419" );
	script_name( "CentOS Update for apr CESA-2011:0844 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apr'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "apr on CentOS 4" );
	script_tag( name: "insight", value: "The Apache Portable Runtime (APR) is a portability library used by the
  Apache HTTP Server and other projects. It provides a free library of C data
  structures and routines.

  The fix for CVE-2011-0419 (released via RHSA-2011:0507) introduced an
  infinite loop flaw in the apr_fnmatch() function when the APR_FNM_PATHNAME
  matching flag was used. A remote attacker could possibly use this flaw to
  cause a denial of service on an application using the apr_fnmatch()
  function. (CVE-2011-1928)

  Note: This problem affected httpd configurations using the 'Location'
  directive with wildcard URLs. The denial of service could have been
  triggered during normal operation. It did not specifically require a
  malicious HTTP request.

  This update also addresses additional problems introduced by the rewrite of
  the apr_fnmatch() function, which was necessary to address the
  CVE-2011-0419 flaw.

  All apr users should upgrade to these updated packages, which contain a
  backported patch to correct this issue. Applications using the apr library,
  such as httpd, must be restarted for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "apr", rpm: "apr~0.9.4~26.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "apr-devel", rpm: "apr-devel~0.9.4~26.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

