func wmi_proc_prop( handle, procName ){
	if( !procName ){
		query = "Select * from Win32_Process";
	}
	else {
		query = "Select * from Win32_Process Where Name = " + raw_string( 0x22 ) + procName + raw_string( 0x22 );
	}
	procList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( procList, "NTSTATUS" ) ) || !procList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: procList );
}
func wmi_proc_all( handle, procName ){
	if( !procName ){
		query = "Select Caption from Win32_Process";
	}
	else {
		query = "Select Caption from Win32_Process Where Name = " + raw_string( 0x22 ) + procName + raw_string( 0x22 );
	}
	procList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( procName, "NTSTATUS" ) ) || !procList){
		return ( 0 );
	}
	procList = ereg_replace( pattern: "\\|[0-9a-zA-Z]+", string: procList, replace: "" );
	return procList;
}
func wmi_proc_path( handle, procName ){
	if( !procName ){
		query = "Select ExecutablePath from Win32_Process";
	}
	else {
		query = "Select ExecutablePath from Win32_Process Where Name = " + raw_string( 0x22 ) + procName + raw_string( 0x22 );
	}
	procList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( procList, "NTSTATUS" ) ) || !procList){
		return ( 0 );
	}
	procList = ereg_replace( pattern: "\\|[0-9a-zA-Z]+", string: procList, replace: "" );
	return procList;
}

