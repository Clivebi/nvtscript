func wmi_hardware_logicaldisk( handle ){
	query = "Select * From Win32_LogicalDisk";
	ldList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( ldList, "NTSTATUS" ) ) || !ldList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: ldList );
}
func wmi_hardware_displayconf( handle ){
	query = "Select * From Win32_DisplayConfiguration";
	confList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( confList, "NTSTATUS" ) ) || !confList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: confList );
}
func wmi_hardware_floppydrive( handle ){
	query = "Select * From Win32_FloppyDrive";
	flpyList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( flpyList, "NTSTATUS" ) ) || !flpyList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: flpyList );
}
func wmi_hardware_floppycontroller( handle ){
	query = "Select * From Win32_FloppyController";
	flpyList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( flpyList, "NTSTATUS" ) ) || !flpyList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: flpyList );
}
func wmi_hardware_idecontroller( handle ){
	query = "Select * From Win32_IDEController";
	ideList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( ideList, "NTSTATUS" ) ) || !ideList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: ideList );
}
func wmi_hardware_ip4routetable( handle ){
	query = "Select * From Win32_IP4RouteTable";
	ip4List = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( ip4List, "NTSTATUS" ) ) || !ip4List){
		return ( 0 );
	}
	return wmi_misc_split_res( List: ip4List );
}
func wmi_hardware_get_keyboard( handle ){
	query = "Select * From Win32_Keyboard";
	keyList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( keyList, "NTSTATUS" ) ) || !keyList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: keyList );
}
func wmi_hardware_processor( handle ){
	query = "Select * From Win32_Processor";
	procList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( procList, "NTSTATUS" ) ) || !procList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: procList );
}
func wmi_hardware_scsicontroller( handle ){
	query = "Select * From Win32_SCSIController";
	scsiList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( scsiList, "NTSTATUS" ) ) || !scsiList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: scsiList );
}
func wmi_hardware_scsicontrollerdevice( handle ){
	query = "Select * From Win32_SCSIControllerDevice";
	scsiList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( scsiList, "NTSTATUS" ) ) || !scsiList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: scsiList );
}
func wmi_hardware_serialport( handle ){
	query = "Select * From Win32_SerialPort";
	portList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( portList, "NTSTATUS" ) ) || !portList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: portList );
}
func wmi_hardware_serialportconf( handle ){
	query = "Select * From Win32_SerialPortConfiguration";
	portList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( portList, "NTSTATUS" ) ) || !portList){
		return ( 0 );
	}
	return wmi_misc_split_res( List: portList );
}
func wmi_misc_software( handle, filePath, instDate ){
	if( !filePath && !instDate ){
		query = "Select Path from Win32_SoftwareElement";
	}
	else {
		if( instDate ){
			query = "Select * from Win32_SoftwareElement Where InstallDate = " + raw_string( 0x22 ) + instDate + raw_string( 0x22 );
		}
		else {
			if(filePath){
				query = "Select Version from Win32_SoftwareElement Where Path = " + raw_string( 0x22 ) + filePath + raw_string( 0x22 );
			}
		}
	}
	winAll = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( winAll, "NTSTATUS" ) || !winAll )){
		return ( 0 );
	}
	return wmi_misc_split_res( List: winAll );
}

