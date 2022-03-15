if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108641" );
	script_version( "2021-10-04T08:45:32+0000" );
	script_tag( name: "last_modification", value: "2021-10-04 08:45:32 +0000 (Mon, 04 Oct 2021)" );
	script_tag( name: "creation_date", value: "2019-09-10 11:01:30 +0000 (Tue, 10 Sep 2019)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Printer Job Language (PJL) / Printer Command Language (PCL) Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "dont_print_on_printers.sc" );
	script_require_ports( "Services/hp-pjl", 2000, 2501, 9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9112, 9113, 9114, 9115, 9116, 10001 );
	script_xref( name: "URL", value: "http://www.maths.usyd.edu.au/u/psz/ps.html" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20130416193817/http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=bpl04568" );
	script_xref( name: "URL", value: "http://h10032.www1.hp.com/ctg/Manual/bpl13208.pdf" );
	script_xref( name: "URL", value: "http://h10032.www1.hp.com/ctg/Manual/bpl13207.pdf" );
	script_xref( name: "URL", value: "https://developers.hp.com/system/files/PJL_Technical_Reference_Manual.pdf" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20151122184353/http://download.brother.com/welcome/doc002907/Tech_Manual_Y.pdf" );
	script_tag( name: "summary", value: "The remote service supports the Printer Job Language (PJL)
  and/or Printer Command Language (PCL) protocol and answered to a PJL and/or PCL request.

  This indicates the remote device is probably a printer running JetDirect.

  Through PJL/PCL, users can submit printing jobs, transfer files to or from the printers, change
  some settings, etc." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("list_array_func.inc.sc");
require("network_func.inc.sc");
require("pcl_pjl.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("string_hex_func.inc.sc");
default_ports = pcl_pjl_get_default_ports();
ports = service_get_ports( proto: "hp-pjl", default_port_list: default_ports );
vt_strings = get_vt_strings();
final_ports = make_array();
reqs = pcl_pjl_get_detect_requests( vt_strings: vt_strings );
for default_port in default_ports {
	if(!in_array( search: default_port, array: ports, part_match: FALSE ) && get_port_state( default_port )){
		ports = make_list( ports,
			 default_port );
	}
}
for port in ports {
	if( service_verify( port: port, proto: "hp-pjl" ) ) {
		final_ports[port] = TRUE;
	}
	else {
		final_ports[port] = FALSE;
	}
}
for final_port in keys( final_ports ) {
	port = final_port;
	in_kb = final_ports[final_port];
	if(!in_kb && service_is_known( port: port )){
		continue;
	}
	if(hexstr( unknown_banner_get( port: port, dontfetch: TRUE ) ) == "aeaeaeaeae" || !in_kb){
		s = open_sock_tcp( port );
		if(!s){
			continue;
		}
		identified = FALSE;
		report = "";
		final_report = "";
		pjl_support = FALSE;
		pcl_support = FALSE;
		for req in keys( reqs ) {
			response_check = reqs[req];
			send( socket: s, data: req );
			r = recv( socket: s, length: 1024 );
			if(!r){
				continue;
			}
			if(ContainsString( r, "@PJL" ) && ContainsString( r, response_check )){
				pjl_support = TRUE;
			}
			if(ContainsString( r, "PCL" ) && ContainsString( r, response_check )){
				pcl_support = TRUE;
			}
			if( ContainsString( r, "@PJL INFO ID\r\n" ) ){
				identified = TRUE;
				lines = split( buffer: r, keep: FALSE );
				if(max_index( lines ) >= 1 && strlen( lines[1] ) > 0){
					info = ereg_replace( string: lines[1], pattern: "^ *\"(.*)\" *$", replace: "\\1" );
					if(strlen( info ) == 0){
						info = lines[1];
					}
					if(!info){
						continue;
					}
					if(report){
						report += "\n";
					}
					report = strcat( report, "The device INFO ID is:\n", info );
					set_kb_item( name: "hp-pjl/banner/available", value: TRUE );
					set_kb_item( name: "hp-pjl/" + port + "/banner", value: chomp( info ) );
				}
			}
			else {
				if( ContainsString( r, "@PJL INFO PRODINFO\r\n" ) ){
					identified = TRUE;
					mac = verify_register_mac_address( data: r, desc: "Printer Job Language (PJL) / Printer Command Language (PCL) Detection", prefix_string: "HWAddress = " );
					if(mac){
						if(report){
							report += "\n";
						}
						report = strcat( report, "The device MAC Address is:\n", mac );
					}
					if(!ContainsString( r, "?" )){
						lines = split( buffer: r, keep: FALSE );
						if(max_index( lines ) >= 1){
							for line in lines {
								line = chomp( line );
								if(!line || line == "@PJL INFO PRODINFO"){
									continue;
								}
								set_kb_item( name: "hp-pjl/" + port + "/prodinfo", value: line );
							}
						}
					}
				}
				else {
					if( ContainsString( r, "@PJL INFO STATUS\r\n" ) || "@PJL USTATUS DEVICE\r\n" ){
						identified = TRUE;
						if(!ContainsString( r, "?" )){
							lines = split( buffer: r, keep: FALSE );
							if(max_index( lines ) >= 1){
								for line in lines {
									line = chomp( line );
									if(!line || line == "@PJL INFO STATUS" || line == "@PJL USTATUS DEVICE" || line == "\f@PJL INFO STATUS" || line == "\f@PJL USTATUS DEVICE"){
										continue;
									}
									set_kb_item( name: "hp-pjl/" + port + "/status", value: line );
								}
							}
						}
					}
					else {
						if(ContainsString( r, response_check )){
							identified = TRUE;
						}
					}
				}
			}
		}
		close( s );
		if(identified){
			if(pjl_support || pcl_support){
				final_report = "The device supports: ";
			}
			if(pjl_support){
				final_report += "PJL";
				set_kb_item( name: "hp-pjl/port", value: port );
			}
			if(pcl_support){
				if(pjl_support){
					final_report += ", ";
				}
				final_report += "PCL";
				set_kb_item( name: "hp-pcl/port", value: port );
			}
			if( final_report && report ) {
				report = final_report += "\n" + report;
			}
			else {
				if(final_report){
					report = final_report;
				}
			}
			log_message( port: port, data: report );
			if(!in_kb){
				if(pjl_support){
					service_register( port: port, proto: "hp-pjl" );
				}
				if(pcl_support){
					service_register( port: port, proto: "hp-pcl" );
				}
				pcl_pjl_register_all_ports();
			}
		}
	}
}
exit( 0 );

