if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18263" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "TFTP backdoor" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Malware" );
	script_dependencies( "tftpd_dir_trav.sc" );
	script_require_udp_ports( "Services/udp/tftp", 69 );
	script_mandatory_keys( "tftp/filename_available" );
	script_tag( name: "solution", value: "Disinfect your system." );
	script_tag( name: "summary", value: "A TFTP server is running on this port.
  However, while trying to fetch some file, we retrieved an executable file.

  This is probably a backdoor." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("port_service_func.inc.sc");
func report_backdoor( port, file, type ){
	var port, file, type, report;
	report = "A TFTP server is running on this port. However, while trying to fetch " + file + ", we got a " + type + " executable file.\n\nThis is probably a backdoor.";
	security_message( port: port, proto: "udp", data: report );
	if(port == 69){
		set_kb_item( name: "tftp/backdoor", value: TRUE );
	}
	set_kb_item( name: "tftp/" + port + "/backdoor", value: TRUE );
	exit( 0 );
}
port = service_get_port( default: 69, proto: "tftp", ipproto: "udp" );
nb = 0;
for(i = 0;i < 1000;i++){
	fname = get_kb_item( "tftp/" + port + "/filename/" + i );
	if(!fname){
		exit( 0 );
	}
	fcontent = get_kb_item( "tftp/" + port + "/filecontent/" + i );
	if(!fcontent){
		exit( 0 );
	}
	mz = substr( fcontent, 0, 1 );
	if( mz == "MZ" || mz == "ZM" ) {
		report_backdoor( port: port, file: fname, type: "MS" );
	}
	else {
		if( mz == "\x01\x08" ) {
			report_backdoor( port: port, file: fname, type: "a.out NMAGIC" );
		}
		else {
			if( mz == "\x01\x0B" ) {
				report_backdoor( port: port, file: fname, type: "a.out ZMAGIC" );
			}
			else {
				if( mz == "CC" ) {
					report_backdoor( port: port, file: fname, type: "a.out QMAGIC" );
				}
				else {
					if( mz == "\x01\xDF" ) {
						report_backdoor( port: port, file: fname, type: "XCOFF32" );
					}
					else {
						if( mz == "\x01\xEF" ) {
							report_backdoor( port: port, file: fname, type: "XCOFF64" );
						}
						else {
							if(substr( fcontent, 0, 3 ) == "\x7fELF"){
								report_backdoor( port: port, file: fname, type: "ELF" );
							}
						}
					}
				}
			}
		}
	}
}
exit( 99 );

