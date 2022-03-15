func wmi_os_version( handle ){
	var info = GetOperatingSystemInformation(handle);
    if(info){
        return info.Version;
    }
    return "";
}
func wmi_os_type( handle ){
	var info = GetOperatingSystemInformation(handle);
    if(info){
        return info.ProductType;
    }
    return "";
}
func wmi_os_sp( handle ){
	var info = GetOperatingSystemInformation(handle);
    if(info){
        return info.CSDVersion;
    }
    return "";
}
func wmi_os_hotfix( handle ){
	query = "Select HotfixID from Win32_QuickFixEngineering";
	hfList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( hfList, "NTSTATUS" ) ) || !hfList){
		return ( 0 );
	}
	j = 0;
	hfList = split( buffer: hfList, sep: "\\n", keep: 0 );
	for(i = 1;i < max_index( hfList );i++){
		hotfix = eregmatch( pattern: "^(KB|M|Q)[0-9v]+", string: hfList[i] );
		if(hotfix[0] != NULL){
			hf[j] = hotfix[0];
			j++;
		}
	}
	if( hf != NULL ){
		return hf;
	}
	else {
		return ( 0 );
	}
}
func wmi_os_buildnumber( handle ){
	var info = GetOperatingSystemInformation(handle);
    if(info){
        return info.BuildNumber;
    }
    return "";
}
func wmi_os_windir( handle ){
	var info = GetOperatingSystemInformation(handle);
    if(info){
        return info.WindowsDirectory;
    }
    return "";
}
func wmi_os_sysdir( handle ){
	var info = GetOperatingSystemInformation(handle);
    if(info){
        return info.SystemDirectory;
    }
    return "";
}
func wmi_os_all( handle ){
	query = "Select * from Win32_OperatingSystem";
	winAll = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( winAll, "NTSTATUS" ) || !winAll )){
		return ( 0 );
	}
	return wmi_misc_split_res( List: winAll );
}

