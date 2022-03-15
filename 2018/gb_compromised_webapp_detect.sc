if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108459" );
	script_version( "2021-05-28T06:21:45+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-28 06:21:45 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-09-06 13:30:22 +0200 (Thu, 06 Sep 2018)" );
	script_name( "Compromised Web Application Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Malware" );
	script_dependencies( "webmirror.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "www/compromised_webapp/detected" );
	script_xref( name: "URL", value: "https://gwillem.gitlab.io/2018/08/30/magentocore.net_skimmer_most_aggressive_to_date/" );
	script_tag( name: "summary", value: "This script reports if a web page of the remote host was compromised by known
  Skimmer / Malware code." );
	script_tag( name: "insight", value: "Currently the Indicator of compromise (IOC) of the following
  known Skimmer / Malware code is evaluated / reported:

  - MagentoCore skimmer" );
	script_tag( name: "impact", value: "A compromised web page might have various impact depending on the deployed code. Please
  check the referenced links for more information on the impact of specific code." );
	script_tag( name: "solution", value: "Inspect all reported web pages / URLs and remove the related source code. Further analysis on entry points,
  possible additional deployed backdoors or user accounts and similar is required." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
compromisedList = get_kb_list( "www/" + host + "/" + port + "/content/compromised_webapp" );
if(!compromisedList || !is_array( compromisedList )){
	exit( 99 );
}
compromisedList = sort( compromisedList );
report = "";
for compromisedItem in compromisedList {
	info = split( buffer: compromisedItem, sep: "#----#", keep: FALSE );
	if(!info){
		continue;
	}
	compPage = info[0];
	compCode = info[1];
	compInfo = info[2];
	if(!compCode){
		compInfo = "No source code currently collected";
	}
	if(!compInfo){
		compInfo = "No information currently available";
	}
	if(report){
		report += "\n\n";
	}
	report += "Compromised page on the target: " + compPage + "\n";
	report += "IOC source code: " + compCode + "\n";
	report += "Resource/link/further info: " + compInfo;
}
security_message( port: port, data: "The following Indicator of compromise (IOC) were found:\n\n" + report );
exit( 0 );

