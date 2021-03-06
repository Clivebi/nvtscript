if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107637" );
	script_version( "2019-06-20T12:01:41+0000" );
	script_tag( name: "last_modification", value: "2019-06-20 12:01:41 +0000 (Thu, 20 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-04-06 13:44:05 +0200 (Sat, 06 Apr 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Advantech WebAccess Detection (Consolidation)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_advantech_webaccess_detect.sc", "gb_advantech_webaccess_detect_win.sc" );
	script_mandatory_keys( "advantech/webaccess/detected" );
	script_tag( name: "summary", value: "Reports on findings if an installation of
  Advantech WebAccess has been found on the target system." );
	script_xref( name: "URL", value: "https://www.advantech.com/industrial-automation/webaccess" );
	exit( 0 );
}
CPE = "cpe:/a:advantech:advantech_webaccess";
require("host_details.inc.sc");
version = "unknown";
extra = "\nConcluded from:";
for proto in make_list( "smb",
	 "http" ) {
	version_list = get_kb_list( "advantech/webaccess/" + proto + "/*/version" );
	for ver in version_list {
		if(ver != "unknown" && version == "unknown"){
			version = ver;
			CPE += ":" + version;
			break;
		}
	}
}
if(!isnull( concl = get_kb_item( "advantech/webaccess/smb/0/concluded" ) )){
	insloc = get_kb_item( "advantech/webaccess/smb/0/location" );
	extra += "\nLocal Detection over SMB:\n";
	extra += "  Concluded: " + concl + "\n";
	extra += "  Location: " + insloc + "\n";
	register_product( cpe: CPE, location: insloc, port: 0, service: "smb-login" );
}
if(http_ports = get_kb_list( "advantech/webaccess/http/port" )){
	extra += "\nRemote Detection over HTTP(s):\n";
	for port in http_ports {
		concl = get_kb_item( "advantech/webaccess/http/" + port + "/concluded" );
		loc = get_kb_item( "advantech/webaccess/http/" + port + "/location" );
		extra += "  Port: " + port + "/tcp\n";
		extra += "  Concluded: " + concl + "\n";
		extra += "  Location: " + loc + "\n";
		register_product( cpe: CPE, location: loc, port: port, service: "www" );
	}
}
report = build_detection_report( app: "Advantech WebAccess", version: version, install: "/", cpe: CPE );
if(extra){
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

