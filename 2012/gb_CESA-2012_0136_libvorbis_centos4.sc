if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-February/018435.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881233" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:53:54 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-0444" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2012:0136" );
	script_name( "CentOS Update for libvorbis CESA-2012:0136 centos4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvorbis'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "libvorbis on CentOS 4" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The libvorbis packages contain runtime libraries for use in programs that
  support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary, patent-and
  royalty-free, general-purpose compressed audio format.

  A heap-based buffer overflow flaw was found in the way the libvorbis
  library parsed Ogg Vorbis media files. If a specially-crafted Ogg Vorbis
  media file was opened by an application using libvorbis, it could cause the
  application to crash or, possibly, execute arbitrary code with the
  privileges of the user running the application. (CVE-2012-0444)

  Users of libvorbis should upgrade to these updated packages, which contain
  a backported patch to correct this issue. The desktop must be restarted
  (log out, then log back in) for this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "libvorbis", rpm: "libvorbis~1.1.0~4.el4.5", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvorbis-devel", rpm: "libvorbis-devel~1.1.0~4.el4.5", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

