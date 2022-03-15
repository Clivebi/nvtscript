CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812894" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_cve_id( "CVE-2018-10951", "CVE-2018-10949", "CVE-2018-10950" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-05-31 11:07:20 +0530 (Thu, 31 May 2018)" );
	script_name( "Zimbra Collaboration Suite Multiple Vulnerabilities(02)-May18" );
	script_tag( name: "summary", value: "This host is running Zimbra Collaboration
  Suite and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to -

  - GetServer, GetAllServers, or GetAllActiveServers call in the Admin SOAP API.

  - Discrepancy between the 'HTTP 404 - account is not active' and
    'HTTP 401 - must authenticate' errors.

  - Verbose error messages containing a stack dump, tracing data, or full
    user-context dump." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to read zimbraSSLPrivateKey, do account enumeration and expose
  information." );
	script_tag( name: "affected", value: "Synacor Zimbra Collaboration Suite (ZCS)
  8.7 before 8.7.11.Patch3 and 8.6 before 8.6.0.Patch10." );
	script_tag( name: "solution", value: "For versions 8.7.x upgrade to version
  8.7.11.Patch3 or later, for versions 8.6.x upgrade to version 8.6.0.Patch10
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.zimbra.com" );
	script_xref( name: "URL", value: "https://bugzilla.zimbra.com/show_bug.cgi?id=108963" );
	script_xref( name: "URL", value: "https://bugzilla.zimbra.com/show_bug.cgi?id=108962" );
	script_xref( name: "URL", value: "https://bugzilla.zimbra.com/show_bug.cgi?id=108894" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zimbra_admin_console_detect.sc" );
	script_mandatory_keys( "zimbra_web/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!zimport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: zimport, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( IsMatchRegexp( vers, "^8\\.7\\." ) && version_is_less( version: vers, test_version: "8.7.12" ) ){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.7.11.Patch3", install_path: path );
	security_message( data: report, port: zimport );
	exit( 0 );
}
else {
	if(vers == "8.6.0"){
		report = report_fixed_ver( installed_version: vers, fixed_version: "8.6.0.Patch10", install_path: path );
		security_message( data: report, port: zimport );
		exit( 0 );
	}
}
exit( 99 );

