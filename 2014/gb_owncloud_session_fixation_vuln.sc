CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804286" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-2047" );
	script_bugtraq_id( 66227 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-05-06 18:00:55 +0530 (Tue, 06 May 2014)" );
	script_name( "ownCloud Session Fixation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with ownCloud and is prone to session fixation
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the application which while establishing a new session,
does not invalidate an existing session identifier and assign a new one." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal the authenticated
sessions and gain unauthorized access." );
	script_tag( name: "affected", value: "ownCloud Server 6.x before version 6.0.2" );
	script_tag( name: "solution", value: "Upgrade to ownCloud version 6.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://owncloud.org/about/security/advisories/oC-SA-2014-001" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ownPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ownVer = get_app_version( cpe: CPE, port: ownPort )){
	exit( 0 );
}
if(version_in_range( version: ownVer, test_version: "6.0.0", test_version2: "6.0.1" )){
	report = report_fixed_ver( installed_version: ownVer, vulnerable_range: "6.0.0 - 6.0.1" );
	security_message( port: ownPort, data: report );
	exit( 0 );
}

