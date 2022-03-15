if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-January/018395.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881199" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:40:59 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2012:0062" );
	script_name( "CentOS Update for t1lib CESA-2012:0062 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 't1lib'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "t1lib on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The t1lib library allows you to rasterize bitmaps from PostScript Type 1
  fonts.

  Two heap-based buffer overflow flaws were found in the way t1lib processed
  Adobe Font Metrics (AFM) files. If a specially-crafted font file was opened
  by an application linked against t1lib, it could cause the application to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2010-2642, CVE-2011-0433)

  An invalid pointer dereference flaw was found in t1lib. A specially-crafted
  font file could, when opened, cause an application linked against t1lib to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2011-0764)

  A use-after-free flaw was found in t1lib. A specially-crafted font file
  could, when opened, cause an application linked against t1lib to crash or,
  potentially, execute arbitrary code with the privileges of the user
  running the application. (CVE-2011-1553)

  An off-by-one flaw was found in t1lib. A specially-crafted font file could,
  when opened, cause an application linked against t1lib to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the application. (CVE-2011-1554)

  An out-of-bounds memory read flaw was found in t1lib. A specially-crafted
  font file could, when opened, cause an application linked against t1lib to
  crash. (CVE-2011-1552)

  Red Hat would like to thank the Evince development team for reporting
  CVE-2010-2642. Upstream acknowledges Jon Larimer of IBM X-Force as the
  original reporter of CVE-2010-2642.

  All users of t1lib are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. All applications linked
  against t1lib must be restarted for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "t1lib", rpm: "t1lib~5.1.2~6.el6_2.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-apps", rpm: "t1lib-apps~5.1.2~6.el6_2.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-devel", rpm: "t1lib-devel~5.1.2~6.el6_2.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "t1lib-static", rpm: "t1lib-static~5.1.2~6.el6_2.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

