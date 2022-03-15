CPE = "cpe:/a:adobe:flash_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804351" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-0510" );
	script_bugtraq_id( 66241 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-04-01 12:45:19 +0530 (Tue, 01 Apr 2014)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities - 01 Apr14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to some unspecified error caused by improper validation of
user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to conduct denial of service or
potentially execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Flash Player version 12.0.0.77 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade Flash Player to version 13.0.0.182 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1029969" );
	script_xref( name: "URL", value: "https://www.hkcert.org/my_url/en/alert/14033103" );
	script_xref( name: "URL", value: "http://www.pwn2own.com/2014/03/pwn2own-results-thursday-day-two" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: playerVer, test_version: "12.0.0.77" )){
	report = report_fixed_ver( installed_version: playerVer, vulnerable_range: "Equal to 12.0.0.77" );
	security_message( port: 0, data: report );
	exit( 0 );
}

