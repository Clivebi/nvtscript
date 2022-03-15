if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108323" );
	script_version( "2021-03-23T06:51:29+0000" );
	script_tag( name: "last_modification", value: "2021-03-23 06:51:29 +0000 (Tue, 23 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-01-30 11:21:18 +0100 (Tue, 30 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Check for enabled / working Port scanner plugin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "toolcheck.sc" );
	script_exclude_keys( "Host/scanned" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-20.08/en/performance.html#optimizing-the-scan-performance" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-20.08/en/scanning.html?highlight=scanner_plugins_timeout#description-of-scanner-preferences" );
	script_tag( name: "summary", value: "The script reports if:

  - a custom scan configuration is in use without having a Port scanner from
  the 'Port scanners' family enabled.

  - a port scanner plugin was running into a timeout.

  - a required port scanner (e.g. nmap) is not installed." );
	script_tag( name: "solution", value: "Based on the script output please:

  - add a Port scanner plugin from the 'Port scanners' family to this scan
  configuration. Recommended: Nmap (NASL wrapper).

  - either choose a port range for this target containing less ports or raise
  the 'scanner_plugins_timeout' scanner preference to a higher timeout.

  - install the 'nmap' binary/package or make it accessible to the scanner." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(get_kb_item( "Host/scanned" )){
	exit( 0 );
}
mark_dead = get_kb_item( "/ping_host/mark_dead" );
if(!ContainsString( mark_dead, "yes" )){
	exit( 0 );
}
if(ContainsString( get_preference( "unscanned_closed" ), "no" ) || ContainsString( get_preference( "unscanned_closed_udp" ), "no" )){
	exit( 0 );
}
report = "The host wasn't scanned due to the following possible reasons:";
report += "\n\n - No Port scanner plugin from the \"Port scanners\" family is ";
report += "included in this scan configuration. Recommended: Nmap (NASL wrapper).";
report += "\n - The Port scanner plugin reached a timeout during the port scanning ";
report += "phase. Please either choose a port range for this target containing less ports ";
report += "or raise the \"scanner_plugins_timeout\" scanner preference to a higher timeout.";
if(!get_kb_item( "Tools/Present/nmap" )){
	report += "\n - The \"nmap\" binary/package is not installed or not accessible by the scanner.";
}
log_message( port: 0, data: report );
exit( 0 );

