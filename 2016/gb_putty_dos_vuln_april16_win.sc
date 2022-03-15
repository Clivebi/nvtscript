CPE = "cpe:/a:putty:putty";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807915" );
	script_version( "2021-06-01T06:37:42+0000" );
	script_tag( name: "last_modification", value: "2021-06-01 06:37:42 +0000 (Tue, 01 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-04-21 10:16:59 +0530 (Thu, 21 Apr 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-2563" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PuTTY DoS Vulnerability April16 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_putty_portable_detect.sc" );
	script_mandatory_keys( "putty/detected" );
	script_tag( name: "summary", value: "PuTTY is prone to denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The SCP command-line utility (pscp) is missing a bounds-check
  for a stack buffer when processing the SCP-SINK file-size response to a SCP download request." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote servers to conduct a
  DoS attack." );
	script_tag( name: "affected", value: "PuTTY versions 0.59 through 0.66 on Windows." );
	script_tag( name: "solution", value: "Update to version 0.67 or later." );
	script_xref( name: "URL", value: "https://github.com/tintinweb/pub/tree/master/pocs/cve-2016-2563" );
	script_xref( name: "URL", value: "http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-pscp-sink-sscanf.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "0.59", test_version2: "0.66" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "0.67", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

