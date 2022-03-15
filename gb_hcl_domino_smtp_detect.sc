if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144581" );
	script_version( "2020-10-05T09:43:10+0000" );
	script_tag( name: "last_modification", value: "2020-10-05 09:43:10 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-16 06:29:54 +0000 (Wed, 16 Sep 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "HCL / IBM / Lotus Domino Detection (SMTP)" );
	script_tag( name: "summary", value: "SMTP based detection of HCL Domino (formerly Lotus/IBM Domino)." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smtpserver_detect.sc" );
	script_mandatory_keys( "smtp/hcl/domino/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("smtp_func.inc.sc");
port = smtp_get_port( default: 25 );
banner = smtp_get_banner( port: port );
if(banner && IsMatchRegexp( banner, "(HCL|IBM|Lotus) Domino" )){
	set_kb_item( name: "hcl/domino/detected", value: TRUE );
	set_kb_item( name: "hcl/domino/smtp/port", value: port );
	set_kb_item( name: "hcl/domino/smtp/" + port + "/concluded", value: banner );
	version = "unknown";
	vers = eregmatch( pattern: "Release ([^)]+)", string: banner );
	if(!isnull( vers[1] )){
		version = str_replace( string: vers[1], find: "FP", replace: "." );
		version = ereg_replace( string: version, pattern: "( )?HF", replace: ".HF" );
	}
	set_kb_item( name: "hcl/domino/smtp/" + port + "/version", value: version );
}
exit( 0 );

