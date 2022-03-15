CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804384" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2004-1153" );
	script_bugtraq_id( 11934 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-04-10 15:10:46 +0530 (Thu, 10 Apr 2014)" );
	script_name( "Adobe Reader '.ETD File' Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to denial of service
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to the format string error in '.etd' file." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code on
the system and gain sensitive information." );
	script_tag( name: "affected", value: "Adobe Reader version 6.0.0 through 6.0.2 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 6.0.3 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/18478" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2004-12/0147.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Reader/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.0.2" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "6.0.0 - 6.0.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}

