CPE = "cpe:/a:theforeman:foreman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106423" );
	script_version( "$Revision: 12096 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2016-3728" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Foreman Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_foreman_detect.sc" );
	script_mandatory_keys( "foreman/installed" );
	script_tag( name: "summary", value: "Foreman is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The smart proxy TFTP API is vulnerable to arbitrary remote code execution,
as it passes untrusted user input (the PXE template type) to the eval() function causing it to be executed." );
	script_tag( name: "affected", value: "Version 0.2 until 1.11.1 except 1.10.4" );
	script_tag( name: "solution", value: "Upgrade to 1.10.4, 1.11.2 or later." );
	script_xref( name: "URL", value: "https://theforeman.org/security.html#2016-3728" );
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
if(version_in_range( version: version, test_version: "0.2", test_version2: "1.11.1" )){
	if(version != "1.10.4"){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.11.2" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

