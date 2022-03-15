if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-February/015631.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880774" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:0012" );
	script_cve_id( "CVE-2007-2721", "CVE-2008-3520" );
	script_name( "CentOS Update for netpbm CESA-2009:0012 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'netpbm'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "netpbm on CentOS 4" );
	script_tag( name: "insight", value: "The netpbm package contains a library of functions for editing and
  converting between various graphics file formats, including .pbm (portable
  bitmaps), .pgm (portable graymaps), .pnm (portable anymaps), .ppm (portable
  pixmaps), and others.

  An input validation flaw and multiple integer overflows were discovered in
  the JasPer library providing support for JPEG-2000 image format and used in
  the jpeg2ktopam and pamtojpeg2k converters. An attacker could create a
  carefully-crafted JPEG file which could cause jpeg2ktopam to crash or,
  possibly, execute arbitrary code as the user running jpeg2ktopam.
  (CVE-2007-2721, CVE-2008-3520)

  All users are advised to upgrade to these updated packages which contain
  backported patches which resolve these issues." );
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
	if(( res = isrpmvuln( pkg: "netpbm", rpm: "netpbm~10.25~2.1.el4.4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "netpbm-devel", rpm: "netpbm-devel~10.25~2.1.el4.4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "netpbm-progs", rpm: "netpbm-progs~10.25~2.1.el4.4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

