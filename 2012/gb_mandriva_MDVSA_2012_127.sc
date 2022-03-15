if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:127" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831715" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-09 10:25:28 +0530 (Thu, 09 Aug 2012)" );
	script_cve_id( "CVE-2012-3401" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:127" );
	script_name( "Mandriva Update for libtiff MDVSA-2012:127 (libtiff)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtiff'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2011\\.0|mes5\\.2)" );
	script_tag( name: "affected", value: "libtiff on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability was found and corrected in libtiff:

  A heap-based buffer overflow flaw was found in the way tiff2pdf, a
  TIFF image to a PDF document conversion tool, of libtiff, a library
  of functions for manipulating TIFF (Tagged Image File Format) image
  format files, performed write of TIFF image content into particular PDF
  document file, when not properly initialized T2P context struct pointer
  has been provided by tiff2pdf (application requesting the conversion)
  as one of parameters for the routine performing the write. A remote
  attacker could provide a specially-crafted TIFF image format file,
  that when processed by tiff2pdf would lead to tiff2pdf executable
  crash or, potentially, arbitrary code execution with the privileges
  of the user running the tiff2pdf binary (CVE-2012-3401).

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
	if(( res = isrpmvuln( pkg: "libtiff3", rpm: "libtiff3~3.9.5~1.3", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~3.9.5~1.3", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-progs", rpm: "libtiff-progs~3.9.5~1.3", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-static-devel", rpm: "libtiff-static-devel~3.9.5~1.3", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff3", rpm: "lib64tiff3~3.9.5~1.3", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff-devel", rpm: "lib64tiff-devel~3.9.5~1.3", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff-static-devel", rpm: "lib64tiff-static-devel~3.9.5~1.3", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_mes5.2"){
	if(( res = isrpmvuln( pkg: "libtiff3", rpm: "libtiff3~3.8.2~12.8mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff3-devel", rpm: "libtiff3-devel~3.8.2~12.8mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff3-static-devel", rpm: "libtiff3-static-devel~3.8.2~12.8mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-progs", rpm: "libtiff-progs~3.8.2~12.8mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff3", rpm: "lib64tiff3~3.8.2~12.8mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff3-devel", rpm: "lib64tiff3-devel~3.8.2~12.8mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff3-static-devel", rpm: "lib64tiff3-static-devel~3.8.2~12.8mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

