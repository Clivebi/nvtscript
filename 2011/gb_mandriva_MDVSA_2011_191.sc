if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-12/msg00016.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831511" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-12-23 10:36:07 +0530 (Fri, 23 Dec 2011)" );
	script_xref( name: "MDVSA", value: "2011:191" );
	script_cve_id( "CVE-2011-1778" );
	script_name( "Mandriva Update for libarchive MDVSA-2011:191 (libarchive)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libarchive'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_mes5" );
	script_tag( name: "affected", value: "libarchive on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A heap-based buffer overflow flaw was discovered in libarchive. If
  a user were tricked into expanding a specially-crafted ISO 9660
  CD-ROM image or tar archive with an application using libarchive,
  it could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application
  (CVE-2011-1778).

  The updated packages have been patched to correct these issues." );
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
	if(( res = isrpmvuln( pkg: "bsdtar", rpm: "bsdtar~2.5.5~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libarchive2", rpm: "libarchive2~2.5.5~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libarchive-devel", rpm: "libarchive-devel~2.5.5~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libarchive", rpm: "libarchive~2.5.5~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64archive2", rpm: "lib64archive2~2.5.5~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64archive-devel", rpm: "lib64archive-devel~2.5.5~1.1mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
