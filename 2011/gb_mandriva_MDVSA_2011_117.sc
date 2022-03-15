if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-07/msg00006.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831430" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-07-27 14:47:11 +0200 (Wed, 27 Jul 2011)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2011:117" );
	script_cve_id( "CVE-2011-1526" );
	script_name( "Mandriva Update for krb5-appl MDVSA-2011:117 (krb5-appl)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5-appl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2010\\.1)" );
	script_tag( name: "affected", value: "krb5-appl on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A vulnerability was discovered and corrected in krb5-appl:

  ftpd.c in the GSS-API FTP daemon in MIT Kerberos Version 5 Applications
  (aka krb5-appl) 1.0.1 and earlier does not check the krb5_setegid
  return value, which allows remote authenticated users to bypass
  intended group access restrictions, and create, overwrite, delete,
  or read files, via standard FTP commands, related to missing autoconf
  tests in a configure script (CVE-2011-1526).

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
	if(( res = isrpmvuln( pkg: "krb5-appl-clients", rpm: "krb5-appl-clients~1.0~0.3mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-appl-servers", rpm: "krb5-appl-servers~1.0~0.3mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-appl", rpm: "krb5-appl~1.0~0.3mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "krb5-appl-clients", rpm: "krb5-appl-clients~1.0~4.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-appl-servers", rpm: "krb5-appl-servers~1.0~4.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-appl", rpm: "krb5-appl~1.0~4.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

