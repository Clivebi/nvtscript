if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108441" );
	script_version( "$Revision: 12934 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-03 21:41:17 +0100 (Thu, 03 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2018-05-02 10:53:41 +0200 (Wed, 02 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Unknown OS and Service Banner Reporting" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "unknown_services.sc", "find_service_nmap.sc", "os_detection.sc", "find_service_nmap_wrapped.sc" );
	script_mandatory_keys( "unknown_os_or_service/available" );
	script_xref( name: "URL", value: "https://community.greenbone.net/c/vulnerability-tests" );
	script_tag( name: "summary", value: "This NVT consolidates and reports the information collected by
  the following NVTs:

  - Collect banner of unknown services (OID: 1.3.6.1.4.1.25623.1.0.11154)

  - Service Detection (unknown) with nmap (OID: 1.3.6.1.4.1.25623.1.0.66286)

  - Service Detection (wrapped) with nmap (OID: 1.3.6.1.4.1.25623.1.0.108525)

  - OS Detection Consolidation and Reporting (OID: 1.3.6.1.4.1.25623.1.0.105937)

  If you know any of the information reported here, please send the full output to
  the referenced community portal." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(!get_kb_item( "unknown_os_or_service/available" )){
	exit( 0 );
}
nmap_already_reported = make_array();
unknown_os_banners = get_kb_list( "os_detection_report/unknown_os_banner/*/banner" );
if(unknown_os_banners){
	report = "Unknown banners have been collected which might help to identify the OS running on this host. ";
	report += "If these banners containing information about the host OS please report the following information ";
	report += "to https://community.greenbone.net/c/vulnerability-tests:";
	keys = sort( keys( unknown_os_banners ) );
	for key in keys {
		tmp = split( buffer: key, sep: "/", keep: FALSE );
		oid = tmp[2];
		port = tmp[3];
		proto = tmp[4];
		banner_type_short = tmp[5];
		banner = get_kb_item( "os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/banner" );
		type = get_kb_item( "os_detection_report/unknown_os_banner/" + oid + "/" + port + "/" + proto + "/" + banner_type_short + "/type_full" );
		report += "\n\nBanner: " + banner + "\n";
		report += "Identified from: " + type;
		if(port && port != "0"){
			report += " on port " + port + "/" + proto;
		}
	}
	log_message( port: 0, data: report );
}
unknown_service_banners = get_kb_list( "unknown_service_report/unknown_banner/*/report" );
if(unknown_service_banners){
	for unknown_service_banner in keys( unknown_service_banners ) {
		report = "An unknown service is running on this port. If you know this service, please ";
		report += "report the following information to https://community.greenbone.net/c/vulnerability-tests:\n\n";
		tmp = split( buffer: unknown_service_banner, sep: "/", keep: FALSE );
		port = tmp[2];
		banner = get_kb_item( "unknown_service_report/unknown_banner/" + port + "/report" );
		if(banner){
			report += banner;
		}
		nmap_reports = get_kb_list( "unknown_service_report/nmap/*/" + port + "/report" );
		if(nmap_reports){
			keys = sort( keys( nmap_reports ) );
			for nmap_report in keys {
				tmp = split( buffer: nmap_report, sep: "/", keep: FALSE );
				type = tmp[2];
				_report = get_kb_item( "unknown_service_report/nmap/" + type + "/" + port + "/report" );
				if(_report){
					report += "\n\n" + _report;
					nmap_already_reported[type + port] = TRUE;
				}
			}
		}
		log_message( port: port, data: report );
	}
}
nmap_reports = get_kb_list( "unknown_service_report/nmap/*/*/report" );
if(nmap_reports){
	for nmap_report in keys( nmap_reports ) {
		tmp = split( buffer: nmap_report, sep: "/", keep: FALSE );
		type = tmp[2];
		port = tmp[3];
		if(nmap_already_reported[type + port]){
			continue;
		}
		report = get_kb_item( "unknown_service_report/nmap/" + type + "/" + port + "/report" );
		if(report){
			nmap_already_reported[type + port] = TRUE;
			log_message( port: port, data: report );
		}
	}
}
exit( 0 );

