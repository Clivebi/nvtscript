CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803945" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-27 16:50:31 +0530 (Fri, 27 Sep 2013)" );
	script_name( "OTRS Mailbox HTML Injection Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to inject script code
into the OTRS webinterface." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in application's agent mailbox view which fails to properly
sanitize user-supplied input before using it" );
	script_tag( name: "solution", value: "Upgrade to OTRS (Open Ticket Request System) version 2.0.5 or later, or apply the patch
  from the referenced vendor advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with OTRS (Open Ticket Request System) and is prone to
HTML injection vulnerability." );
	script_tag( name: "affected", value: "OTRS (Open Ticket Request System) version 2.0.0 up to and including 2.0.4." );
	script_xref( name: "URL", value: "http://otrs.org/advisory/OSA-2007-01-en/" );
	script_category( ACT_GATHER_INFO );
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
	if(version_in_range( version: vers, test_version: "2.0.0", test_version2: "2.0.4" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "2.0.0 - 2.0.4" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}

