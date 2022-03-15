if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-April/018560.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881231" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:53:34 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-1173" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:0468" );
	script_name( "CentOS Update for libtiff CESA-2012:0468 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtiff'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "libtiff on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The libtiff packages contain a library of functions for manipulating Tagged
  Image File Format (TIFF) files.

  Two integer overflow flaws, leading to heap-based buffer overflows, were
  found in the way libtiff attempted to allocate space for a tile in a TIFF
  image file. An attacker could use these flaws to create a specially-crafted
  TIFF file that, when opened, would cause an application linked against
  libtiff to crash or, possibly, execute arbitrary code. (CVE-2012-1173)

  All libtiff users should upgrade to these updated packages, which contain a
  backported patch to resolve these issues. All running applications linked
  against libtiff must be restarted for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~3.8.2~14.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~3.8.2~14.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

