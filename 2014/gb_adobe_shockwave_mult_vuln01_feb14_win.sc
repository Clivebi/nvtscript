CPE = "cpe:/a:adobe:shockwave_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804096" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-0500", "CVE-2014-0501" );
	script_bugtraq_id( 65490, 65493 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-02-13 12:25:40 +0530 (Thu, 13 Feb 2014)" );
	script_name( "Adobe Shockwave Player Multiple Memory Corruption Vulnerabilities Feb14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave Player and is prone to multiple
memory corruption vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to multiple unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption and compromise a user's system." );
	script_tag( name: "affected", value: "Adobe Shockwave Player version before 12.0.9.149 on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 12.0.9.149 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56740" );
	script_xref( name: "URL", value: "http://helpx.adobe.com/security/products/shockwave/apsb14-06.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_shockwave_player_detect.sc" );
	script_mandatory_keys( "Adobe/ShockwavePlayer/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "12.0.9.149" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.0.9.149" );
	security_message( port: 0, data: report );
	exit( 0 );
}

