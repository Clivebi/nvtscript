if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-November/019019.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881546" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-12-04 09:43:37 +0530 (Tue, 04 Dec 2012)" );
	script_cve_id( "CVE-2012-5134" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:1512" );
	script_name( "CentOS Update for libxml2 CESA-2012:1512 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "libxml2 on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The libxml2 library is a development toolbox providing the implementation
  of various XML standards.

  A heap-based buffer underflow flaw was found in the way libxml2 decoded
  certain entities. A remote attacker could provide a specially-crafted XML
  file that, when opened in an application linked against libxml2, would
  cause the application to crash or, potentially, execute arbitrary code with
  the privileges of the user running the application. (CVE-2012-5134)

  All users of libxml2 are advised to upgrade to these updated packages,
  which contain a backported patch to correct this issue. The desktop must be
  restarted (log out, then log back in) for this update to take effect." );
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "libxml2", rpm: "libxml2~2.7.6~8.el6_3.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-devel", rpm: "libxml2-devel~2.7.6~8.el6_3.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-python", rpm: "libxml2-python~2.7.6~8.el6_3.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxml2-static", rpm: "libxml2-static~2.7.6~8.el6_3.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

