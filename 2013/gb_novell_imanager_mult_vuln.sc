if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803626" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-3268", "CVE-2013-1088" );
	script_bugtraq_id( 59042, 59450 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-06-04 16:30:14 +0530 (Tue, 04 Jun 2013)" );
	script_name( "Novell iManager Multiple Vulnerabilities" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_family( "General" );
	script_dependencies( "novell_imanager_detect.sc" );
	script_mandatory_keys( "novellimanager/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to perform unauthorized
  actions and gain access to the affected application. Other attacks are also possible." );
	script_tag( name: "affected", value: "Novell iManager version prior to 2.7 SP 6 patch 1." );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Does not refresh a token after a logout action.

  - Does not require multiple steps or explicit confirmation for sensitive
    transactions." );
	script_tag( name: "summary", value: "The host is running Novell iManager and is prone to multiple unspecified
  vulnerabilities." );
	script_tag( name: "solution", value: "Apply the patch." );
	script_xref( name: "URL", value: "https://www.novell.com/support/kb/doc.php?id=7010166" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:novell:imanager",
	 "cpe:/a:netiq:imanager" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!version = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.7.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7 SP 6 patch 1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

