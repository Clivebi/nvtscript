if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803942" );
	script_version( "2021-07-01T11:00:40+0000" );
	script_cve_id( "CVE-2013-3551" );
	script_bugtraq_id( 60117 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2021-07-01 11:00:40 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-26 19:34:00 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-09-27 15:32:31 +0530 (Fri, 27 Sep 2013)" );
	script_name( "OTRS ITSM Ticket Split Information Disclosure Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain access to
  sensitive information." );
	script_tag( name: "vuldetect", value: "Get the installed version and location of OTRS with the help of detect NVT
  and check the OTRS and OTRS:ITSM version is vulnerable or not." );
	script_tag( name: "insight", value: "An error exists in application when handling URLs related to the ticket split
  mechanism." );
	script_tag( name: "solution", value: "Upgrade to OTRS (Open Ticket Request System) version 3.0.20, 3.1.16 and 3.2.7
  or later, and OTRS::ITSM version 3.2.5, 3.1.9 and 3.0.8 or apply the patch from the referenced vendor advisory link." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with OTRS (Open Ticket Request System) or OTRS:ITSM
  and is prone to information disclosure vulnerability." );
	script_tag( name: "affected", value: "OTRS (Open Ticket Request System) version 3.0.x up to and including 3.0.19,
  3.1.x up to and including 3.1.15 and 3.2.x up to and including 3.2.6

  OTRS::ITSM 3.1.0 up to and including 3.1.8, 3.0.0 up to and including 3.0.7
  and 3.2.0 up to and including 3.2.4" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/60117" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53496/" );
	script_xref( name: "URL", value: "http://www.otrs.com/en/open-source/community-news/security-advisories/security-advisory-2013-03/" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:otrs:otrs",
	 "cpe:/a:otrs:otrs_itsm" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( ContainsString( cpe, "cpe:/a:otrs:otrs_itsm" ) ){
	if(version_in_range( version: vers, test_version: "3.1.0", test_version2: "3.1.8" ) || version_in_range( version: vers, test_version: "3.0.0", test_version2: "3.0.7" ) || version_in_range( version: vers, test_version: "3.2.0", test_version2: "3.2.4" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(ContainsString( cpe, "cpe:/a:otrs:otrs" )){
		if(version_in_range( version: vers, test_version: "3.2.0", test_version2: "3.2.6" ) || version_in_range( version: vers, test_version: "3.0.0", test_version2: "3.0.19" ) || version_in_range( version: vers, test_version: "3.1.0", test_version2: "3.1.15" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

