if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:180" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831757" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-12-18 10:06:00 +0530 (Tue, 18 Dec 2012)" );
	script_cve_id( "CVE-2012-5526" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_xref( name: "MDVSA", value: "2012:180" );
	script_name( "Mandriva Update for perl-CGI MDVSA-2012:180 (perl-CGI)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-CGI'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2011\\.0|mes5\\.2)" );
	script_tag( name: "affected", value: "perl-CGI on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability was discovered and corrected in perl-CGI:

  CGI.pm module before 3.63 for Perl does not properly escape newlines in
  (1) Set-Cookie or (2) P3P headers, which might allow remote attackers
  to inject arbitrary headers into responses from applications that
  use CGI.pm (CVE-2012-5526).

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
	if(( res = isrpmvuln( pkg: "perl-CGI", rpm: "perl-CGI~3.530.0~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perl-CGI-Fast", rpm: "perl-CGI-Fast~3.530.0~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_mes5.2"){
	if(( res = isrpmvuln( pkg: "perl-CGI", rpm: "perl-CGI~3.51~0.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perl-CGI-Fast", rpm: "perl-CGI-Fast~3.51~0.2mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

