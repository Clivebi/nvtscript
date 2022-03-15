CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803917" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2008-7276" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-17 19:18:31 +0530 (Tue, 17 Sep 2013)" );
	script_name( "OTRS /tmp/ Directory Restriction Bypass Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow local users to bypass intended access
restrictions via standard filesystem operations." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in Kernel/System/Web/Request.pm which creates a directory
under /tmp/ with 1274 permissions" );
	script_tag( name: "solution", value: "Upgrade to OTRS (Open Ticket Request System) version 2.3.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with OTRS (Open Ticket Request System) and is prone to
restriction bypass vulnerability." );
	script_tag( name: "affected", value: "OTRS (Open Ticket Request System) version before 2.3.2" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OTRS/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_is_less( version: vers, test_version: "2.3.2" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.2" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}

