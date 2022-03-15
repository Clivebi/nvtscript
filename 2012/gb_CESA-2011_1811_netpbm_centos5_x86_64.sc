if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-December/018320.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881332" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:25:43 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2009-4274", "CVE-2011-4516", "CVE-2011-4517" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:1811" );
	script_name( "CentOS Update for netpbm CESA-2011:1811 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'netpbm'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "netpbm on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The netpbm packages contain a library of functions which support programs
  for handling various graphics file formats, including .pbm (Portable Bit
  Map), .pgm (Portable Gray Map), .pnm (Portable Any Map), .ppm (Portable
  Pixel Map), and others.

  Two heap-based buffer overflow flaws were found in the embedded JasPer
  library, which is used to provide support for Part 1 of the JPEG 2000 image
  compression standard in the jpeg2ktopam and pamtojpeg2k tools. An attacker
  could create a malicious JPEG 2000 compressed image file that could cause
  jpeg2ktopam to crash or, potentially, execute arbitrary code with the
  privileges of the user running jpeg2ktopam. These flaws do not affect
  pamtojpeg2k. (CVE-2011-4516, CVE-2011-4517)

  A stack-based buffer overflow flaw was found in the way the xpmtoppm tool
  processed X PixMap (XPM) image files. An attacker could create a malicious
  XPM file that would cause xpmtoppm to crash or, potentially, execute
  arbitrary code with the privileges of the user running xpmtoppm.
  (CVE-2009-4274)

  Red Hat would like to thank Jonathan Foote of the CERT Coordination Center
  for reporting the CVE-2011-4516 and CVE-2011-4517 issues.

  All users of netpbm are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues." );
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
	if(( res = isrpmvuln( pkg: "netpbm", rpm: "netpbm~10.35.58~8.el5_7.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "netpbm-devel", rpm: "netpbm-devel~10.35.58~8.el5_7.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "netpbm-progs", rpm: "netpbm-progs~10.35.58~8.el5_7.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

