if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-12/msg00017.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831514" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-12-23 10:36:10 +0530 (Fri, 23 Dec 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "MDVSA", value: "2011:180" );
	script_cve_id( "CVE-2011-2483" );
	script_name( "Mandriva Update for php-suhosin MDVSA-2011:180 (php-suhosin)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-suhosin'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2010\\.1)" );
	script_tag( name: "affected", value: "php-suhosin on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A vulnerability was discovered and fixed in php-suhosin:
  crypt_blowfish before 1.1, as used in suhosin does not properly
  handle 8-bit characters, which makes it easier for context-dependent
  attackers to determine a cleartext password by leveraging knowledge
  of a password hash (CVE-2011-2483).

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
	if(( res = isrpmvuln( pkg: "php-suhosin", rpm: "php-suhosin~0.9.32.1~0.6mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "php-suhosin", rpm: "php-suhosin~0.9.32.1~0.6mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

