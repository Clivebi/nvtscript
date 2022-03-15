CPE = "cpe:/a:cisco:telepresence_server_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105378" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-04-22T08:55:01+0000" );
	script_cve_id( "CVE-2015-6284" );
	script_name( "Cisco TelePresence Server Denial of Service Vulnerability " );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150916-tps" );
	script_tag( name: "impact", value: "Successful exploitation of the buffer overflow vulnerability may result in a crash of the server, resulting in a DoS condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "This vulnerability is documented in Cisco bug ID CSCuu28277" );
	script_tag( name: "solution", value: "Updates are available" );
	script_tag( name: "summary", value: "Cisco TelePresence Server contains a buffer overflow vulnerability in the Conference Control Protocol API that could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition." );
	script_tag( name: "affected", value: "All releases of Cisco TelePresence Server software prior to 4.1(2.33) running on the following products are affected by this vulnerability:

Cisco TelePresence Server 7010

Cisco TelePresence Server MSE 8710

Cisco TelePresence Server on Multiparty Media 310

Cisco TelePresence Server on Multiparty Media 320

Cisco TelePresence Server on Virtual Machine" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "2021-04-22 08:55:01 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-09-21 12:52:46 +0200 (Mon, 21 Sep 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_telepresence_server_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cisco_telepresence_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!model = get_kb_item( "cisco_telepresence_server/model" )){
	exit( 0 );
}
if(!IsMatchRegexp( model, "^7010$" ) && !IsMatchRegexp( model, "^8710$" ) && !IsMatchRegexp( model, "Media 3(1|2)0" ) && model != "VM"){
	exit( 99 );
}
fix = "4.1.2.33";
report_fix = "4.1(2.33)";
report_vers = vers;
vers = str_replace( string: vers, find: "(", replace: "." );
vers = str_replace( string: vers, find: ")", replace: "" );
if(version_is_less( version: vers, test_version: fix )){
	report = "Installed version: " + report_vers + "\n" + "Fixed version:     " + report_fix + "\n" + "Model:             " + model + "\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

