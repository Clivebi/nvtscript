if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103908" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-02-18 11:22:35 +0100 (Tue, 18 Feb 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Home Network Administration Protocol (HNAP) Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts
  to determine if the Home Network Administration Protocol (HNAP) is supported." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
url = "/HNAP1";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf || !ContainsString( buf, "soap:Envelope" ) || !ContainsString( buf, "SOAPActions" ) || !ContainsString( buf, "http://purenetworks.com/HNAP1" )){
	url = "/HNAP1/";
	req = http_get( item: url, port: port );
	buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
}
if(buf && ContainsString( buf, "soap:Envelope" ) && ContainsString( buf, "SOAPActions" ) && ContainsString( buf, "http://purenetworks.com/HNAP1" )){
	if(ContainsString( buf, "<VendorName>" )){
		vendor = eregmatch( pattern: "<VendorName>([^<]+)</VendorName>", string: buf );
		if(!isnull( vendor[1] )){
			set_kb_item( name: "HNAP/" + port + "/vendor", value: vendor[1] );
			set_kb_item( name: "HNAP/" + port + "/vendor_concluded", value: vendor[0] );
			set_kb_item( name: "HNAP/vendor", value: TRUE );
			report += "\nVendor:   " + vendor[1];
		}
	}
	if(ContainsString( buf, "<ModelName>" )){
		model = eregmatch( pattern: "<ModelName>([^<]+)</ModelName>", string: buf );
		if(!isnull( model[1] )){
			set_kb_item( name: "HNAP/" + port + "/model", value: model[1] );
			set_kb_item( name: "HNAP/" + port + "/model_concluded", value: model[0] );
			set_kb_item( name: "HNAP/model", value: TRUE );
			report += "\nModel:    " + model[1];
		}
	}
	if(ContainsString( buf, "<FirmwareVersion>" )){
		fw = eregmatch( pattern: "<FirmwareVersion>([^<]+)</FirmwareVersion>", string: buf );
		if(!isnull( fw[1] )){
			set_kb_item( name: "HNAP/" + port + "/firmware", value: fw[1] );
			set_kb_item( name: "HNAP/" + port + "/firmware_concluded", value: fw[0] );
			set_kb_item( name: "HNAP/firmware", value: TRUE );
			report += "\nFirmware: " + fw[1];
		}
	}
	if(ContainsString( buf, "<HardwareVersion>" )){
		hw = eregmatch( pattern: "<HardwareVersion>([^<]+)</HardwareVersion>", string: buf );
		if(!isnull( hw[1] )){
			set_kb_item( name: "HNAP/" + port + "/hardware", value: hw[1] );
			set_kb_item( name: "HNAP/" + port + "/hardware_concluded", value: hw[0] );
			set_kb_item( name: "HNAP/hardware", value: TRUE );
			report += "\nHardware: " + hw[1];
		}
	}
	conclUrl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
	set_kb_item( name: "HNAP/port", value: port );
	set_kb_item( name: "HNAP/" + port + "/detected", value: TRUE );
	set_kb_item( name: "HNAP/" + port + "/conclurl", value: conclUrl );
	_report = "The remote host supports the Home Network Administration Protocol (HNAP).\n\n";
	_report += "Discovery-URL: " + conclUrl;
	if(strlen( report ) > 0){
		_report += "\n\nExtracted Device information:\n" + report;
	}
	log_message( data: _report, port: port );
}
exit( 0 );

