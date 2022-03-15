if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111091" );
	script_version( "2021-01-14T10:02:07+0000" );
	script_tag( name: "last_modification", value: "2021-01-14 10:02:07 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-03-25 15:12:12 +0100 (Fri, 25 Mar 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Report NVT debug logs" );
	script_category( ACT_END );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_add_preference( name: "Report NVT debug logs", type: "checkbox", value: "no", id: 1 );
	script_tag( name: "summary", value: "The script reports possible issues within VTs.

  For best results set 'optimize_test', 'unscanned_closed' and 'unscanned_closed_udp'
  within the 'Scanner Preferences' to 'no'." );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
enable_log = script_get_preference( name: "Report NVT debug logs", id: 1 );
if(enable_log && ContainsString( enable_log, "no" )){
	exit( 0 );
}
report = "The following issues have been identified: \n\n";
items = get_kb_list( "vt_debug_empty/*" );
if(!isnull( items )){
	items = sort( items );
	for item in items {
		x = split( buffer: item, sep: "#-#", keep: FALSE );
		x_oid = x[0];
		x_variable = x[1];
		x_function = x[2];
		if(ContainsString( x_function, "http_keepalive_recv_body" ) || ContainsString( x_function, "http_keepalive_check_connection" ) || ContainsString( x_function, "http_gunzip" )){
			continue;
		}
		found = TRUE;
		if( ContainsString( x_variable, "port" ) && ContainsString( x_function, "get_app_location" ) ){
			report += "- " + x_oid + ": variable \"" + x_variable + "\" passed to function \"" + x_function + "\" is empty (Might be a false positive)\n";
		}
		else {
			report += "- " + x_oid + ": variable \"" + x_variable + "\" passed to function \"" + x_function + "\" is empty\n";
		}
	}
}
items = get_kb_list( "vt_debug_cpe_syntax/*" );
if(!isnull( items )){
	items = sort( items );
	for item in items {
		x = split( buffer: item, sep: "#-#", keep: FALSE );
		x_oid = x[0];
		x_function = x[1];
		x_content = x[2];
		x_variable = x[3];
		found = TRUE;
		report += "- " + x_oid + ": " + x_function + ": Malformed CPE \"" + x_content + "\" given to \"" + x_variable + "\" parameter\n";
	}
}
items = get_kb_list( "vt_debug_no_array/*" );
if(!isnull( items )){
	items = sort( items );
	for item in items {
		x = split( buffer: item, sep: "#-#", keep: FALSE );
		x_oid = x[0];
		x_variable = x[1];
		x_function = x[2];
		found = TRUE;
		report += "- " + x_oid + ": variable \"" + x_variable + "\" passed to function \"" + x_function + "\" is not an array\n";
	}
}
items = get_kb_list( "vt_debug_cgi_scanning_disabled/*" );
if(!isnull( items )){
	items = sort( items );
	for item in items {
		x = split( buffer: item, sep: "#-#", keep: FALSE );
		x_oid = x[0];
		x_variable = x[1];
		found = TRUE;
		report += "- " + x_oid + ": VT is calling \"" + x_variable + "\" while cgi scanning is disabled\n";
	}
}
items = get_kb_list( "vt_debug_misc/*" );
if(!isnull( items )){
	items = sort( items );
	for item in items {
		x = split( buffer: item, sep: "#-#", keep: FALSE );
		x_oid = x[0];
		x_text = x[1];
		found = TRUE;
		report += "- " + x_oid + ": " + x_text + "\n";
	}
}
optimize_test_enabled = get_preference( "optimize_test" );
if(optimize_test_enabled && ContainsString( optimize_test_enabled, "no" )){
	report += "\nNote: Scanner preference \"optimize_test\" is set to \"no\". Because of this VTs calling http_cgi_dirs() or http_get_port() while cgi scanning is disabled are not reported.";
}
if(found){
	log_message( port: 0, data: chomp( report ) );
}
exit( 0 );

