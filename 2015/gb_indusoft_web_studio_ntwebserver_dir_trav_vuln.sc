CPE = "cpe:/a:schneider_electric:indusoft_web_studio";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806642" );
	script_version( "$Revision: 14057 $" );
	script_cve_id( "CVE-2014-0780" );
	script_bugtraq_id( 67056 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:02:00 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-07 13:44:29 +0530 (Mon, 07 Dec 2015)" );
	script_name( "InduSoft Web Studio 'NTWebServer' Directory Traversal Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with InduSoft Web
  Studio and is prone to directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  'NTWebServer' (test web server installed with InduSoft Web Studio)." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to read files outside the web root and possibly perform arbitrary
  code execution." );
	script_tag( name: "affected", value: "InduSoft Web Studio version 7.1
  before SP2 Patch 4 on Windows." );
	script_tag( name: "solution", value: "Upgrade to InduSoft Web Studio version
  7.1 SP2 Patch 4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-14-107-02" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_schneider_indusoft_consolidation.sc" );
	script_mandatory_keys( "schneider_indusoft/installed" );
	script_xref( name: "URL", value: "http://www.indusoft.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!studioVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( studioVer, "^(7.1\\.)" )){
	if(version_is_less( version: studioVer, test_version: "7.1.2.4" )){
		report = report_fixed_ver( installed_version: studioVer, fixed_version: "7.1.2.4" );
		security_message( data: report );
		exit( 0 );
	}
}

