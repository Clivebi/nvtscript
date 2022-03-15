func wmi_svc_prop( handle, svcName ){
	if( !svcName ){
		query = "Select * from Win32_Service";
	}
	else {
		query = "Select * from Win32_Service Where Name = " + raw_string( 0x22 ) + svcName + raw_string( 0x22 );
	}
	svcList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( svcList, "NTSTATUS" ) ) || !svcList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: svcList );
}
func wmi_svc( handle, svcName ){
	if( !svcName ){
		query = "Select Caption from Win32_Service";
	}
	else {
		query = "Select Caption from Win32_Service Where Name = " + raw_string( 0x22 ) + svcName + raw_string( 0x22 );
	}
	svcList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( svcList, "NTSTATUS" ) ) || !svcList){
		return ( 0 );
	}
	svcList = ereg_replace( pattern: "\\|", string: svcList, replace: " - " );
	return svcList;
}
func wmi_svc_state( handle, svcName ){
	if( !svcName ){
		query = "Select State from Win32_Service";
	}
	else {
		query = "Select State from Win32_Service Where Name = " + raw_string( 0x22 ) + svcName + raw_string( 0x22 );
	}
	svcList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( svcList, "NTSTATUS" ) ) || !svcList){
		return ( 0 );
	}
	svcList = ereg_replace( pattern: "\\|", string: svcList, replace: " - " );
	return svcList;
}
func wmi_svc_path( handle, svcName ){
	if( !svcName ){
		query = "Select PathName from Win32_Service";
	}
	else {
		query = "Select PathName from Win32_Service Where Name = " + raw_string( 0x22 ) + svcName + raw_string( 0x22 );
	}
	svcList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( svcList, "NTSTATUS" ) ) || !svcList){
		return ( 0 );
	}
	svcList = ereg_replace( pattern: "[.a-zA-Z0-9_ ]+\\|" + "\\\"?", string: svcList, replace: "" );
	return svcList;
}

