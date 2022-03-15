func wmi_rsop_accesstoken( handle ){
	query = "Select * from RSOP_UserPrivilegeRight where precedence=1";
	rsopList = wmi_query_rsop( wmi_handle: handle, query: query );
	if(( ContainsString( rsopList, "NTSTATUS" ) ) || !rsopList){
		return ( 0 );
	}
	return rsopList;
}
func wmi_rsop_auditpolicy( handle, select ){
	if( select ){
		query = "Select " + select + " from RSOP_AuditPolicy where precedence=1";
	}
	else {
		query = "Select * from RSOP_AuditPolicy where precedence=1";
	}
	rsopList = wmi_query_rsop( wmi_handle: handle, query: query );
	if(( ContainsString( rsopList, "NTSTATUS" ) ) || !rsopList){
		return ( 0 );
	}
	return rsopList;
}
func wmi_rsop_policysetting( handle ){
	query = "Select * from RSOP_PolicySetting where precedence=1";
	rsopList = wmi_query_rsop( wmi_handle: handle, query: query );
	if(( ContainsString( rsopList, "NTSTATUS" ) ) || !rsopList){
		return ( 0 );
	}
	return rsopList;
}
func wmi_rsop_userprivilegeright( handle, select ){
	if( select ){
		query = "select " + select + " from RSOP_UserPrivilegeRight where precedence=1";
	}
	else {
		query = "select * from RSOP_UserPrivilegeRight where precedence=1";
	}
	rsopList = wmi_query_rsop( wmi_handle: handle, query: query );
	if(( ContainsString( rsopList, "NTSTATUS" ) ) || !rsopList){
		return ( 0 );
	}
	return rsopList;
}
func wmi_rsop_lockoutpolicy( handle ){
	query = "Select * from RSOP_SecuritySettingBoolean where precedence=1";
	rsopList = wmi_query_rsop( wmi_handle: handle, query: query );
	if(( ContainsString( rsopList, "NTSTATUS" ) ) || !rsopList){
		return ( 0 );
	}
	return rsopList;
}
func wmi_rsop_passwdpolicy( handle ){
	query = "Select * from RSOP_SecuritySettingNumeric where precedence=1";
	rsopList = wmi_query_rsop( wmi_handle: handle, query: query );
	if(( ContainsString( rsopList, "NTSTATUS" ) ) || !rsopList){
		return ( 0 );
	}
	return rsopList;
}

