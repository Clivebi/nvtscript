if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-04/msg00025.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831380" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-04-29 17:38:42 +0200 (Fri, 29 Apr 2011)" );
	script_xref( name: "MDVSA", value: "2011:078" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-5022" );
	script_name( "Mandriva Update for libtiff MDVSA-2011:078 (libtiff)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtiff'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2010\\.1|2010\\.0)" );
	script_tag( name: "affected", value: "libtiff on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in libtiff:

  The libtiff OJPEG decoder contains a heap buffer overflow when decoding
  certain malformed data (CVE-2009-5022).

  The updated packages have been patched to correct this issue." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
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
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "libtiff3", rpm: "libtiff3~3.9.2~2.5mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~3.9.2~2.5mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-progs", rpm: "libtiff-progs~3.9.2~2.5mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-static-devel", rpm: "libtiff-static-devel~3.9.2~2.5mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~3.9.2~2.5mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff3", rpm: "lib64tiff3~3.9.2~2.5mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff-devel", rpm: "lib64tiff-devel~3.9.2~2.5mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff-static-devel", rpm: "lib64tiff-static-devel~3.9.2~2.5mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.0"){
	if(( res = isrpmvuln( pkg: "libtiff3", rpm: "libtiff3~3.9.1~4.5mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~3.9.1~4.5mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-progs", rpm: "libtiff-progs~3.9.1~4.5mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff-static-devel", rpm: "libtiff-static-devel~3.9.1~4.5mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~3.9.1~4.5mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff3", rpm: "lib64tiff3~3.9.1~4.5mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff-devel", rpm: "lib64tiff-devel~3.9.1~4.5mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64tiff-static-devel", rpm: "lib64tiff-static-devel~3.9.1~4.5mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

