if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-10/msg00028.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831473" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "MDVSA", value: "2011:153" );
	script_cve_id( "CVE-2006-1168", "CVE-2011-2896", "CVE-2011-2895" );
	script_name( "Mandriva Update for libxfont MDVSA-2011:153 (libxfont)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libxfont'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2010\\.1)" );
	script_tag( name: "affected", value: "libxfont on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been discovered and corrected in libxfont:

  The LZW decompressor in (1) the BufCompressedFill function in
  fontfile/decompress.c in X.Org libXfont before 1.4.4 and (2)
  compress/compress.c in 4.3BSD, as used in zopen.c in OpenBSD before
  3.8, FreeBSD, NetBSD, FreeType 2.1.9, and other products, does not
  properly handle code words that are absent from the decompression
  table when encountered, which allows context-dependent attackers
  to trigger an infinite loop or a heap-based buffer overflow, and
  possibly execute arbitrary code, via a crafted compressed stream,
  a related issue to CVE-2006-1168 and CVE-2011-2896 (CVE-2011-2895).

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
if(release == "MNDK_mes5"){
	if(( res = isrpmvuln( pkg: "libxfont1", rpm: "libxfont1~1.3.3~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxfont1-devel", rpm: "libxfont1-devel~1.3.3~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxfont1-static-devel", rpm: "libxfont1-static-devel~1.3.3~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxfont", rpm: "libxfont~1.3.3~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xfont1", rpm: "lib64xfont1~1.3.3~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xfont1-devel", rpm: "lib64xfont1-devel~1.3.3~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xfont1-static-devel", rpm: "lib64xfont1-static-devel~1.3.3~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "libxfont1", rpm: "libxfont1~1.4.1~1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxfont1-devel", rpm: "libxfont1-devel~1.4.1~1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxfont1-static-devel", rpm: "libxfont1-static-devel~1.4.1~1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libxfont", rpm: "libxfont~1.4.1~1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xfont1", rpm: "lib64xfont1~1.4.1~1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xfont1-devel", rpm: "lib64xfont1-devel~1.4.1~1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64xfont1-static-devel", rpm: "lib64xfont1-static-devel~1.4.1~1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

