CPE = "cpe:/a:mcafee:web_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804839" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-6064" );
	script_bugtraq_id( 69556 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-09-09 17:31:29 +0530 (Tue, 09 Sep 2014)" );
	script_name( "McAfee Web Gateway Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with McAfee Web
  Gateway and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in admin
  interface while viewing the top level Accounts tab" );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  authenticated remote attacker to gain access to SHA1 hashed MWG administrator
  password information." );
	script_tag( name: "affected", value: "McAfee Web Gateway before 7.3.2.9 and
  7.4.x before 7.4.2" );
	script_tag( name: "solution", value: "Upgrade to McAfee Web Gateway version
  7.3.2.9 or 7.4.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1030675" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_mcafee_web_gateway_detect.sc" );
	script_mandatory_keys( "McAfee/Web/Gateway/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!mwgPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
mwgVer = get_app_version( cpe: CPE, port: mwgPort );
if(!mwgVer){
	exit( 0 );
}
if(version_is_less( version: mwgVer, test_version: "7.3.2.9" )){
	report = report_fixed_ver( installed_version: mwgVer, fixed_version: "7.3.2.9" );
	security_message( port: mwgPort, data: report );
	exit( 0 );
}
if(IsMatchRegexp( mwgVer, "^7\\.4" )){
	if(version_is_less( version: mwgVer, test_version: "7.4.2" )){
		report = report_fixed_ver( installed_version: mwgVer, fixed_version: "7.4.2" );
		security_message( port: mwgPort, data: report );
		exit( 0 );
	}
}

