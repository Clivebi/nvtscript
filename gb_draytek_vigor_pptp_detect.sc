if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108735" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-04-02 08:40:07 +0000 (Thu, 02 Apr 2020)" );
	script_name( "DrayTek Vigor Detection (PPTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "pptp_detect.sc" );
	script_mandatory_keys( "pptp/vendor_string/detected" );
	script_tag( name: "summary", value: "Detection of DrayTek Vigor devices via PPTP.

  The script checks the vendor string of the device previously gathered via the PPTP Protocol and attempts to
  detect the presence of a DrayTek Vigor device." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1723, proto: "pptp" );
if(!vendor = get_kb_item( "pptp/" + port + "/vendor_string" )){
	exit( 0 );
}
if(!hostname = get_kb_item( "pptp/" + port + "/hostname" )){
	exit( 0 );
}
if(!IsMatchRegexp( vendor, "DrayTek" ) || !IsMatchRegexp( hostname, "Vigor" )){
	exit( 0 );
}
version = "unknown";
concluded = "\n  - Vendor String: " + vendor + "\n  - Hostname:      " + hostname;
set_kb_item( name: "draytek/vigor/detected", value: TRUE );
set_kb_item( name: "draytek/vigor/pptp/detected", value: TRUE );
set_kb_item( name: "draytek/vigor/pptp/port", value: port );
set_kb_item( name: "draytek/vigor/pptp/" + port + "/concluded", value: concluded );
set_kb_item( name: "draytek/vigor/pptp/" + port + "/version", value: version );
exit( 0 );

