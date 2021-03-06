CPE = "cpe:/a:exim:exim";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106485" );
	script_version( "$Revision: 12338 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-23 10:52:32 +0700 (Fri, 23 Dec 2016)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2016-9963" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Exim Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SMTP problems" );
	script_dependencies( "gb_exim_detect.sc" );
	script_require_ports( "Services/smtp", 25 );
	script_mandatory_keys( "exim/installed" );
	script_tag( name: "summary", value: "Exim is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "If several conditions are met, Exim leaks private information to a remote
attacker." );
	script_tag( name: "impact", value: "A remote attacker may obtain private information." );
	script_tag( name: "affected", value: "Exim 4.69 until 4.87." );
	script_tag( name: "solution", value: "Update to Exim 4.87.1 or later." );
	script_xref( name: "URL", value: "https://bugs.exim.org/show_bug.cgi?id=1996" );
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
if(version_in_range( version: version, test_version: "4.69", test_version2: "4.87" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.87.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

