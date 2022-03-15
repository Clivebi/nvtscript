CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803947" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2008-1515" );
	script_bugtraq_id( 74733 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-28 13:08:01 +0530 (Sat, 28 Sep 2013)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "OTRS SOAP Security Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with
  OTRS (Open Ticket Request System) and is prone to security bypass
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in SOAP interface which
  fails to properly validate user credentials before performing certain actions." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read and modify objects via the OTRS SOAP interface." );
	script_tag( name: "affected", value: "OTRS (Open Ticket Request System)
  version 2.1.0 before 2.1.8 and 2.2.0 before 2.2.6" );
	script_tag( name: "solution", value: "Upgrade to OTRS version 2.1.8 or 2.2.6
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!otrsport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!otrsVer = get_app_version( cpe: CPE, port: otrsport )){
	exit( 0 );
}
if(IsMatchRegexp( otrsVer, "^2\\.(1|2)" )){
	if(version_in_range( version: otrsVer, test_version: "2.1.0", test_version2: "2.1.7" ) || version_in_range( version: otrsVer, test_version: "2.2.0", test_version2: "2.2.5" )){
		security_message( port: otrsport );
		exit( 0 );
	}
}

