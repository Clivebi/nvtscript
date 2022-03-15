CPE = "cpe:/a:open-xchange:open-xchange_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811132" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2015-1588" );
	script_bugtraq_id( 74350 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:55:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-06-21 15:24:33 +0530 (Wed, 21 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) Server Multiple Cross Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with
  Open-Xchange (OX) Server and is prone to multiple cross site scripting
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the sanitation and
  cleaner engine does not properly filter HTML code from user-supplied input
  before displaying the input. A remote user can cause arbitrary scripting
  code to be executed by the target user's browser." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML in the browser of an
  unsuspecting user. This can lead to session hijacking or triggering unwanted
  actions via the web interface (sending mail, deleting data etc.). Potential
  attack vectors are E-Mail (via attachments) or Drive." );
	script_tag( name: "affected", value: "Open-Xchange (OX) Server version 6 before
  7.6.1-rev21." );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) Server version
  7.6.1-rev21 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/535388/100/1100/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_server_detect.sc" );
	script_mandatory_keys( "open_xchange_server/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!oxsPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
oxsVer = get_app_version( cpe: CPE, port: oxsPort );
if(!oxsVer){
	exit( 0 );
}
oxRev = get_kb_item( "open_xchange_server/" + oxsPort + "/rev" );
if(oxRev){
	oxsVer = oxsVer + "." + oxRev;
	if(IsMatchRegexp( oxsVer, "^(6|7)" )){
		if(version_in_range( version: oxsVer, test_version: "6.20.7.15", test_version2: "7.6.1.20" )){
			report = report_fixed_ver( installed_version: oxsVer, fixed_version: "7.6.1-rev21" );
			security_message( data: report, port: oxsPort );
			exit( 0 );
		}
	}
}

