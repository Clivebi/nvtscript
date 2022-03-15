if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:023" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831553" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-03-09 19:18:09 +0530 (Fri, 09 Mar 2012)" );
	script_cve_id( "CVE-2012-0823" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "MDVSA", value: "2012:023" );
	script_name( "Mandriva Update for libvpx MDVSA-2012:023 (libvpx)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvpx'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2011\\.0|2010\\.1)" );
	script_tag( name: "affected", value: "libvpx on Mandriva Linux 2011.0,
  Mandriva Linux 2010.1" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in libvpx:

  VP8 Codec SDK (libvpx) before 1.0.0 Duclair allows remote attackers
  to cause a denial of service (application crash) via (1) unspecified
  corrupt input or (2) by starting decoding from a P-frame, which
  triggers an out-of-bounds read, related to the clamping of motion
  vectors in SPLITMV blocks (CVE-2012-0823).

  The updated packages have been patched to correct this issue." );
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
if(release == "MNDK_2011.0"){
	if(( res = isrpmvuln( pkg: "libvpx0", rpm: "libvpx0~0.9.7~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvpx-devel", rpm: "libvpx-devel~0.9.7~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvpx-utils", rpm: "libvpx-utils~0.9.7~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64vpx0", rpm: "lib64vpx0~0.9.7~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64vpx-devel", rpm: "lib64vpx-devel~0.9.7~0.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "libvpx0", rpm: "libvpx0~0.9.7~0.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvpx-devel", rpm: "libvpx-devel~0.9.7~0.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libvpx-utils", rpm: "libvpx-utils~0.9.7~0.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64vpx0", rpm: "lib64vpx0~0.9.7~0.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64vpx-devel", rpm: "lib64vpx-devel~0.9.7~0.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

