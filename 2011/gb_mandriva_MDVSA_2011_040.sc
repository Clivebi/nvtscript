if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-03/msg00001.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831342" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "MDVSA", value: "2011:040" );
	script_cve_id( "CVE-2011-1002" );
	script_name( "Mandriva Update for pango MDVSA-2011:040 (pango)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pango'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2010\\.1|2010\\.0)" );
	script_tag( name: "affected", value: "pango on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in pango:

  It was discovered that pango did not check for memory reallocation
  failures in hb_buffer_ensure() function.  This could trigger a NULL
  pointer dereference in hb_buffer_add_glyph(), where possibly untrusted
  input is used as an index used for accessing members of the incorrectly
  reallocated array, resulting in the use of NULL address as the base
  array address.  This can result in application crash or, possibly,
  code execution (CVE-2011-1002).

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
	if(( res = isrpmvuln( pkg: "libpango1.0_0", rpm: "libpango1.0_0~1.28.0~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpango1.0_0-modules", rpm: "libpango1.0_0-modules~1.28.0~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpango1.0-devel", rpm: "libpango1.0-devel~1.28.0~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pango", rpm: "pango~1.28.0~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pango-doc", rpm: "pango-doc~1.28.0~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pango1.0_0", rpm: "lib64pango1.0_0~1.28.0~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pango1.0_0-modules", rpm: "lib64pango1.0_0-modules~1.28.0~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pango1.0-devel", rpm: "lib64pango1.0-devel~1.28.0~1.2mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.0"){
	if(( res = isrpmvuln( pkg: "libpango1.0_0", rpm: "libpango1.0_0~1.26.1~1.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpango1.0_0-modules", rpm: "libpango1.0_0-modules~1.26.1~1.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpango1.0-devel", rpm: "libpango1.0-devel~1.26.1~1.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pango", rpm: "pango~1.26.1~1.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pango-doc", rpm: "pango-doc~1.26.1~1.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pango1.0_0", rpm: "lib64pango1.0_0~1.26.1~1.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pango1.0_0-modules", rpm: "lib64pango1.0_0-modules~1.26.1~1.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64pango1.0-devel", rpm: "lib64pango1.0-devel~1.26.1~1.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

