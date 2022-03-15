if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-05/msg00016.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831398" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-23 16:55:31 +0200 (Mon, 23 May 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_xref( name: "MDVSA", value: "2011:092" );
	script_cve_id( "CVE-2010-4334" );
	script_name( "Mandriva Update for perl-IO-Socket-SSL MDVSA-2011:092 (perl-IO-Socket-SSL)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-IO-Socket-SSL'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2010\\.1" );
	script_tag( name: "affected", value: "perl-IO-Socket-SSL on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in perl-IO-Socket-SSL:

  IO::Socket::SSL Perl module 1.35, when verify_mode is not VERIFY_NONE,
  fails open to VERIFY_NONE instead of throwing an error when a
  ca_file/ca_path cannot be verified, which allows remote attackers to
  bypass intended certificate restrictions (CVE-2010-4334).

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
	if(( res = isrpmvuln( pkg: "perl-IO-Socket-SSL", rpm: "perl-IO-Socket-SSL~1.330.0~1.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

