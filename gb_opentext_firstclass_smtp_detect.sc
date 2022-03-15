if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113608" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-12-02 13:30:00 +0200 (Mon, 02 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenText FirstClass Detection (SMTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smtpserver_detect.sc" );
	script_require_ports( "Services/smtp", 25, 587 );
	script_mandatory_keys( "smtp/opentext/firstclass/detected" );
	script_tag( name: "summary", value: "Checks whether OpenText FirstClass is present on
  the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.opentext.com/products-and-solutions/products/specialty-technologies/firstclass" );
	exit( 0 );
}
require("host_details.inc.sc");
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
buf = smtp_get_banner( port: port );
if(IsMatchRegexp( buf, "FirstClass [A-Z]?SMTP" )){
	replace_kb_item( name: "opentext/firstclass/detected", value: TRUE );
	set_kb_item( name: "opentext/firstclass/smtp/detected", value: TRUE );
	set_kb_item( name: "opentext/firstclass/smtp/port", value: port );
	ver = eregmatch( string: buf, pattern: "FirstClass [A-Z]?SMTP [^\n]*Server v([0-9.]+)", icase: TRUE );
	if(!isnull( ver[1] )){
		set_kb_item( name: "opentext/firstclass/smtp/concluded", value: ver[0] );
		set_kb_item( name: "opentext/firstclass/smtp/version", value: ver[1] );
	}
}
exit( 0 );

