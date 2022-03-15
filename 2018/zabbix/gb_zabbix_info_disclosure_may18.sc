CPE = "cpe:/a:zabbix:zabbix";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812869" );
	script_version( "2021-06-07T02:00:27+0000" );
	script_cve_id( "CVE-2017-2826" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-07 02:00:27 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 17:50:00 +0000 (Wed, 13 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-05-02 16:58:57 +0530 (Wed, 02 May 2018)" );
	script_name( "Zabbix Server Information Disclosure Vulnerability May18" );
	script_tag( name: "summary", value: "Zabbix server is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Zabbix server unable
  to sanitize against a specially crafted iConfig proxy request." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to make requests from an active Zabbix proxy and cause the Zabbix server to
  send the configuration information of any Zabbix proxy." );
	script_tag( name: "affected", value: "Zabbix server version 2.4.X" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://talosintelligence.com/vulnerability_reports/TALOS-2017-0327" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "zabbix_web_detect.sc" );
	script_mandatory_keys( "Zabbix/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!zport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: zport, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^2\\.4\\." )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: zport, data: report );
	exit( 0 );
}
exit( 0 );

