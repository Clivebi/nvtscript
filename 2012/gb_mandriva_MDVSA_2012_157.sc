if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:157" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831740" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-10-05 09:46:28 +0530 (Fri, 05 Oct 2012)" );
	script_cve_id( "CVE-2012-3535" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:157" );
	script_name( "Mandriva Update for openjpeg MDVSA-2012:157 (openjpeg)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjpeg'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2011\\.0" );
	script_tag( name: "affected", value: "openjpeg on Mandriva Linux 2011.0" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A security issue was identified and fixed in openjpeg:

  A heap-based buffer overflow was found in the way OpenJPEG, an
  open-source JPEG 2000 codec written in C language, performed parsing
  of JPEG2000 image files. A remote attacker could provide a specially
  crafted JPEG 2000 file, which when opened in an application linked
  against openjpeg would lead to that application crash, or, potentially
  arbitrary code execution with the privileges of the user running the
  application (CVE-2012-3535).

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
	if(( res = isrpmvuln( pkg: "libopenjpeg2", rpm: "libopenjpeg2~1.3~8.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libopenjpeg-devel", rpm: "libopenjpeg-devel~1.3~8.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64openjpeg2", rpm: "lib64openjpeg2~1.3~8.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64openjpeg-devel", rpm: "lib64openjpeg-devel~1.3~8.2", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

