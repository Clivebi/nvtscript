CPE = "cpe:/a:barracudadrive:barracudadrive";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804610" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2014-2526" );
	script_bugtraq_id( 66269 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-06-02 11:00:40 +0530 (Mon, 02 Jun 2014)" );
	script_name( "BarracudaDrive Multiple XSS Vulnerabilities -01 June14" );
	script_tag( name: "summary", value: "This host is running BarracudaDrive and is prone to multiple XSS
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
HTML and script code in a user's browser session in the context of a
vulnerable site." );
	script_tag( name: "affected", value: "BarracudaDrive before version 6.7" );
	script_tag( name: "solution", value: "Upgrade to BarracudaDrive version 6.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SecPod_BarracudaDrive_Mult_XSS_Vuln.txt" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_barracuda_drive_detect.sc" );
	script_mandatory_keys( "BarracudaDrive/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!bdPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
bdVer = get_app_version( cpe: CPE, port: bdPort );
if(!bdVer){
	exit( 0 );
}
if(version_is_less( version: bdVer, test_version: "6.7" )){
	report = report_fixed_ver( installed_version: bdVer, fixed_version: "6.7" );
	security_message( port: bdPort, data: report );
	exit( 0 );
}

