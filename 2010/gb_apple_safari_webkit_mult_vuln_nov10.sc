CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801641" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)" );
	script_cve_id( "CVE-2010-3803", "CVE-2010-3804", "CVE-2010-3805", "CVE-2010-3808", "CVE-2010-3809", "CVE-2010-3810", "CVE-2010-3811", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-3816", "CVE-2010-3817", "CVE-2010-3818", "CVE-2010-3819", "CVE-2010-3820", "CVE-2010-3821", "CVE-2010-3822", "CVE-2010-3823", "CVE-2010-3824", "CVE-2010-3826" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Apple Safari Webkit Multiple Vulnerabilities - Nov10" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4455" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42264/" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2010//Nov/msg00002.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_safari_detect_win_900003.sc" );
	script_mandatory_keys( "AppleSafari/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to bypass certain security
  restrictions, conduct spoofing attacks, or compromise a user's system." );
	script_tag( name: "affected", value: "Apple Safari versions prior to 5.0.3." );
	script_tag( name: "insight", value: "For more information about vulnerabilities, refer the links mentioned in
  references." );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 5.0.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.33.19.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Safari 5.0.3 (5.33.19.4)", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

