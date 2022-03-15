CPE = "cpe:/a:rafael_garcia-suarez:safe";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100672" );
	script_version( "2021-07-14T12:36:58+0000" );
	script_bugtraq_id( 40302 );
	script_cve_id( "CVE-2010-1168" );
	script_tag( name: "last_modification", value: "2021-07-14 12:36:58 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Perl Safe Module 'reval()' and 'rdo()' Restriction-Bypass Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_perl_modules_ssh_login_detect.sc" );
	script_mandatory_keys( "perl/ssh-login/modules/safe/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40302" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-1168" );
	script_xref( name: "URL", value: "http://permalink.gmane.org/gmane.comp.security.oss.general/2932" );
	script_xref( name: "URL", value: "http://blogs.perl.org/users/rafael_garcia-suarez/2010/03/new-safepm-fixes-security-hole.html" );
	script_xref( name: "URL", value: "http://cpansearch.perl.org/src/RGARCIA/Safe-2.27/Changes" );
	script_xref( name: "URL", value: "http://search.cpan.org/~rgarcia/Safe-2.27/Safe.pm" );
	script_tag( name: "summary", value: "The Perl Safe module is prone to multiple restriction-bypass
  vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploits could allow an attacker to execute arbitrary
  Perl code outside of the restricted root." );
	script_tag( name: "affected", value: "Versions prior to 2.25 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more
  information." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "2.25" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.25", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

