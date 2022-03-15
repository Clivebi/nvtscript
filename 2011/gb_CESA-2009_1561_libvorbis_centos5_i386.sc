if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-November/016323.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880793" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "CESA", value: "2009:1561" );
	script_cve_id( "CVE-2009-3379" );
	script_name( "CentOS Update for libvorbis CESA-2009:1561 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvorbis'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "libvorbis on CentOS 5" );
	script_tag( name: "insight", value: "The libvorbis packages contain runtime libraries for use in programs that
  support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary, patent-and
  royalty-free, general-purpose compressed audio format.

  Multiple flaws were found in the libvorbis library. A specially-crafted Ogg
  Vorbis media format file (Ogg) could cause an application using libvorbis
  to crash or, possibly, execute arbitrary code when opened. (CVE-2009-3379)

  Users of libvorbis should upgrade to these updated packages, which contain
  backported patches to correct these issues. The desktop must be restarted
  (log out, then log back in) for this update to take effect." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "libvorbis", rpm: "libvorbis~1.1.2~3.el5_4.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvorbis-devel", rpm: "libvorbis-devel~1.1.2~3.el5_4.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

