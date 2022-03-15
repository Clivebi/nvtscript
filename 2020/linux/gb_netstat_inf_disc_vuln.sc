if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111047" );
	script_version( "2020-10-01T11:33:30+0000" );
	script_tag( name: "last_modification", value: "2020-10-01 11:33:30 +0000 (Thu, 01 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-23 09:50:19 +0000 (Wed, 23 Sep 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_cve_id( "CVE-1999-0650" );
	script_name( "netstat Service Information Disclosure" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Useless services" );
	script_dependencies( "sw_netstat_service_detect.sc" );
	script_mandatory_keys( "netstat/installed" );
	script_tag( name: "summary", value: "The netstat service is exposed on the target machine." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "The netstat service provides sensitive information to remote attackers." );
	script_tag( name: "solution", value: "It is recommended to disable this service if not used." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_kb_item( "netstat/port" )){
	exit( 0 );
}
report = "The netstat service was detected on the target machine.";
security_message( data: report, port: port );
exit( 0 );

