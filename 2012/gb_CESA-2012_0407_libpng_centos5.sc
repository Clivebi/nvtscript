if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-March/018507.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881123" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:15:26 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-3045" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:0407" );
	script_name( "CentOS Update for libpng CESA-2012:0407 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "libpng on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The libpng packages contain a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A heap-based buffer overflow flaw was found in the way libpng processed
  compressed chunks in PNG image files. An attacker could create a
  specially-crafted PNG image file that, when opened, could cause an
  application using libpng to crash or, possibly, execute arbitrary code with
  the privileges of the user running the application. (CVE-2011-3045)

  Users of libpng should upgrade to these updated packages, which correct
  this issue. For Red Hat Enterprise Linux 5, they contain a backported
  patch. For Red Hat Enterprise Linux 6, they upgrade libpng to version
  1.2.48. All running applications using libpng must be restarted for the
  update to take effect." );
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
	if(( res = isrpmvuln( pkg: "libpng", rpm: "libpng~1.2.10~16.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpng-devel", rpm: "libpng-devel~1.2.10~16.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

