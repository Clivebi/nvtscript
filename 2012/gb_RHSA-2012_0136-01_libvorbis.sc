if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2012-February/msg00032.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870558" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-21 18:56:58 +0530 (Tue, 21 Feb 2012)" );
	script_cve_id( "CVE-2012-0444" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "RHSA", value: "2012:0136-01" );
	script_name( "RedHat Update for libvorbis RHSA-2012:0136-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvorbis'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(5|4)" );
	script_tag( name: "affected", value: "libvorbis on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
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
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "libvorbis", rpm: "libvorbis~1.1.2~3.el5_7.6", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvorbis-debuginfo", rpm: "libvorbis-debuginfo~1.1.2~3.el5_7.6", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvorbis-devel", rpm: "libvorbis-devel~1.1.2~3.el5_7.6", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_4"){
	if(( res = isrpmvuln( pkg: "libvorbis", rpm: "libvorbis~1.1.0~4.el4.5", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvorbis-debuginfo", rpm: "libvorbis-debuginfo~1.1.0~4.el4.5", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvorbis-devel", rpm: "libvorbis-devel~1.1.0~4.el4.5", rls: "RHENT_4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

