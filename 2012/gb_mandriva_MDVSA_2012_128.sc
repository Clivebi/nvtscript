if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:128" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831716" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-14 10:41:48 +0530 (Tue, 14 Aug 2012)" );
	script_cve_id( "CVE-2012-3410" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:128" );
	script_name( "Mandriva Update for bash MDVSA-2012:128 (bash)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_2011\\.0" );
	script_tag( name: "affected", value: "bash on Mandriva Linux 2011.0" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability was found and corrected in bash:

  A stack-based buffer overflow flaw was found in the way bash, the
  GNU Bourne Again shell, expanded certain /dev/fd file names when
  checking file names ('test' command) and evaluating /dev/fd file
  names in conditinal command expressions. A remote attacker could
  provide a specially-crafted Bash script that, when executed, would
  cause the bash executable to crash (CVE-2012-3410).

  Additionally the official patches 011 to 037 for bash-4.2 has been
  applied which resolves other issues found, including the CVE-2012-3410
  vulnerability." );
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
	if(( res = isrpmvuln( pkg: "bash", rpm: "bash~4.2~9.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bash-doc", rpm: "bash-doc~4.2~9.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

