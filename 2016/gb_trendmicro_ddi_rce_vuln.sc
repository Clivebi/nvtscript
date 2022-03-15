CPE = "cpe:/a:trend_micro:deep_discovery_inspector";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106143" );
	script_version( "2020-08-24T11:37:53+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 11:37:53 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-15 16:17:52 +0700 (Fri, 15 Jul 2016)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-5840" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Trend Micro Deep Discovery Inspector Remote Command Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_trendmicro_deep_discovery_inspector_detect.sc" );
	script_mandatory_keys( "deep_discovery_inspector/detected" );
	script_tag( name: "summary", value: "Trend Micro Deep Discovery Inspector is prone to a remote command
  execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "hotfix_upload.cgi allows remote administrators to execute arbitrary code
  via a crafted string." );
	script_tag( name: "impact", value: "A remote authenticated attacker could potentially attain code execution
  under the context of the root user." );
	script_tag( name: "affected", value: "Version 3.7, 3.8 SP1 (3.81), and 3.8 SP2 (3.82)." );
	script_tag( name: "solution", value: "Install the vendor patch." );
	script_xref( name: "URL", value: "https://esupport.trendmicro.com/solution/en-US/1114281.aspx" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "3.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.7 CP 1263" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.8", test_version2: "3.8.SP2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.8 SP2 (3.82) CP 1203" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

