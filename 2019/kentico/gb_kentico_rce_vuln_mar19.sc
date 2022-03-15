if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113366" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-04-03 10:44:31 +0000 (Wed, 03 Apr 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-15 16:15:00 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-10068" );
	script_name( "Kentico <= 12.0.14 Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_kentico_cms_detect.sc" );
	script_mandatory_keys( "kentico_cms/detected" );
	script_tag( name: "summary", value: "Kentico CMS is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Due to a failure to validate security headers,
  it's possible for a specially crafted request to the staging service to bypass initial authentication
  and proceed to deserialize user-controlled .NET object input. This deserialization
  then leads to unauthenticated remote code execution on the server
  where the Kentico instance is hosted.

  This vulnerability only exists if the Staging Service authentication is not set to X.509." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "Kentico through version 12.0.14." );
	script_tag( name: "solution", value: "Update to version 12.0.15." );
	script_xref( name: "URL", value: "https://devnet.kentico.com/download/hotfixes#securityBugs-v12" );
	exit( 0 );
}
CPE = "cpe:/a:kentico:cms";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "12.0.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.0.15" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

