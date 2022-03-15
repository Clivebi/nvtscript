CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804243" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-1695" );
	script_bugtraq_id( 65844 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-03-04 17:31:09 +0530 (Tue, 04 Mar 2014)" );
	script_name( "OTRS Email HTML Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is running OTRS (Open Ticket Request System) and is prone to html
injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in OTRS core system which fails to properly sanitize
user-supplied input before using it in dynamically generated content" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to steal the victim's
cookie-based authentication credentials." );
	script_tag( name: "affected", value: "Open Ticket Request System (OTRS) version 3.1.x before 3.1.20, 3.2.x before 3.2.15,
and 3.3.x before 3.3.5" );
	script_tag( name: "solution", value: "Upgrade to OTRS version 3.1.20 or 3.2.15 or 3.3.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57018" );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2014-03-xss-issue" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "OTRS/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!otrsport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: otrsport )){
	if(version_in_range( version: vers, test_version: "3.1.0", test_version2: "3.1.19" ) || version_in_range( version: vers, test_version: "3.2.0", test_version2: "3.2.14" ) || version_in_range( version: vers, test_version: "3.3.0", test_version2: "3.3.4" )){
		security_message( port: otrsport );
		exit( 0 );
	}
}

