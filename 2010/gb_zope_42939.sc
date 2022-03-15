if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100779" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2010-09-03 15:15:12 +0200 (Fri, 03 Sep 2010)" );
	script_bugtraq_id( 42939 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-3198" );
	script_name( "Zope Unspecified Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42939" );
	script_xref( name: "URL", value: "https://mail.zope.org/pipermail/zope-announce/2010-September/002247.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_zope_detect.sc" );
	script_mandatory_keys( "zope/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available, please see the references for more information." );
	script_tag( name: "summary", value: "Zope is prone to an unspecified denial-of-service vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause the vulnerable application
  to crash, denying service to legitimate users." );
	script_tag( name: "affected", value: "Versions prior to Zope 2.10.12 and Zope 2.11.7 are vulnerable." );
	exit( 0 );
}
CPE = "cpe:/a:zope:zope";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "2.11", test_version2: "2.11.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.11.7", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.10", test_version2: "2.20.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.10.12", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

