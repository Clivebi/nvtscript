if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:087" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831677" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-06-08 10:19:05 +0530 (Fri, 08 Jun 2012)" );
	script_cve_id( "CVE-2012-2944" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2012:087" );
	script_name( "Mandriva Update for nut MDVSA-2012:087 (nut)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nut'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2011\\.0|mes5\\.2|2010\\.1)" );
	script_tag( name: "affected", value: "nut on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2,
  Mandriva Linux 2010.1" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "A vulnerability has been discovered and corrected in nut:

  Buffer overflow in the addchar function in common/parseconf.c in upsd
  in Network UPS Tools (NUT) before 2.6.4 allows remote attackers to
  execute arbitrary code or cause a denial of service (electric-power
  outage) via a long string containing non-printable characters
  (CVE-2012-2944).

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
	if(( res = isrpmvuln( pkg: "libupsclient1", rpm: "libupsclient1~2.6.1~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut", rpm: "nut~2.6.1~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-cgi", rpm: "nut-cgi~2.6.1~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-devel", rpm: "nut-devel~2.6.1~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-drivers-hal", rpm: "nut-drivers-hal~2.6.1~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-server", rpm: "nut-server~2.6.1~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64upsclient1", rpm: "lib64upsclient1~2.6.1~1.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_mes5.2"){
	if(( res = isrpmvuln( pkg: "libupsclient1", rpm: "libupsclient1~2.2.2~5.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut", rpm: "nut~2.2.2~5.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-cgi", rpm: "nut-cgi~2.2.2~5.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-devel", rpm: "nut-devel~2.2.2~5.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-drivers-hal", rpm: "nut-drivers-hal~2.2.2~5.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-server", rpm: "nut-server~2.2.2~5.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64upsclient1", rpm: "lib64upsclient1~2.2.2~5.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "libupsclient1", rpm: "libupsclient1~2.4.3~3.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut", rpm: "nut~2.4.3~3.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-cgi", rpm: "nut-cgi~2.4.3~3.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-devel", rpm: "nut-devel~2.4.3~3.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-drivers-hal", rpm: "nut-drivers-hal~2.4.3~3.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nut-server", rpm: "nut-server~2.4.3~3.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "lib64upsclient1", rpm: "lib64upsclient1~2.4.3~3.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

