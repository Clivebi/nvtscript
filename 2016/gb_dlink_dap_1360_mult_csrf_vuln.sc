CPE = "cpe:/o:d-link:dap-1360_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810235" );
	script_version( "$Revision: 12431 $" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-10 10:43:14 +0530 (Sat, 10 Dec 2016)" );
	script_name( "D-Link DAP-1360 Multiple CSRF Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dap_detect.sc" );
	script_mandatory_keys( "d-link/dap/model", "d-link/dap/fw_version" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Dec/9" );
	script_xref( name: "URL", value: "http://www.dlink.com" );
	script_tag( name: "summary", value: "This host is a D-Link DAP device which
  is prone to multiple Cross-Site Request Forgery vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple cross
  site request forgery errors in Wi-Fi - WPS method." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to change method in Connection - WPS Method, change parameter
  WPS Enable, reset to unconfigured and read configuration in Information

  - Refresh." );
	script_tag( name: "affected", value: "D-Link DAP-1360, Firmware 1.0.0.
  This model with other firmware versions might be vulnerable as well." );
	script_tag( name: "solution", value: "Update to DAP-1360/A/E1A (f/w version 2.5.4)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "2.5.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.5.4" );
	security_message( port: port, data: report );
}
exit( 0 );

