func wmi_user_sysaccount( handle, usrName ){
	if( !usrName ){
		query = "Select SID from Win32_SystemAccount";
	}
	else {
		query = "Select * from Win32_SystemAccount Where Name = " + raw_string( 0x22 ) + usrName + raw_string( 0x22 );
	}
	usrList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( usrList, "NTSTATUS" ) ) || !usrList){
		return ( 0 );
	}
	return usrList;
}
func wmi_user_useraccount( handle, usrName ){
	if( !usrName ){
		query = "Select SID from Win32_UserAccount";
	}
	else {
		query = "Select * from Win32_UserAccount Where Name = " + raw_string( 0x22 ) + usrName + raw_string( 0x22 );
	}
	usrList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( usrList, "NTSTATUS" ) ) || !usrList){
		return ( 0 );
	}
	return usrList;
}
func wmi_user_group( handle, grpName ){
	if( !usrName ){
		query = "Select SID from Win32_Group";
	}
	else {
		query = "Select * from Win32_Group Where Name = " + raw_string( 0x22 ) + grpName + raw_string( 0x22 );
	}
	grpList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( grpList, "NTSTATUS" ) ) || !grpList){
		return ( 0 );
	}
	return grpList;
}
func wmi_user_groupuser( handle ){
	query = "Select * from Win32_GroupUser";
	grpList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( grpList, "NTSTATUS" ) ) || !grpList){
		return ( 0 );
	}
	return grpList;
}
func wmi_user_is_useraccount_disabled( handle, usrName ){
	if( !usrName ){
		query = "Select Disabled from Win32_UserAccount";
	}
	else {
		query = "Select Disabled from Win32_UserAccount Where Name = " + raw_string( 0x22 ) + usrName + raw_string( 0x22 );
	}
	usrName = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( usrName, "NTSTATUS" ) ) || !usrName){
		return ( 0 );
	}
	return usrName;
}
func wmi_user_is_userpass_changeable( handle, usrName ){
	if( !usrName ){
		query = "Select PasswordChangeable from Win32_UserAccount";
	}
	else {
		query = "Select PasswordChangeable from Win32_UserAccount Where Name =" + raw_string( 0x22 ) + usrName + raw_string( 0x22 );
	}
	usrName = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( usrName, "NTSTATUS" ) ) || !usrName){
		return ( 0 );
	}
	return usrName;
}
func wmi_user_is_userpass_expires( handle, usrName ){
	if( !usrName ){
		query = "Select PasswordExpires from Win32_UserAccount";
	}
	else {
		query = "Select PasswordExpires from Win32_UserAccount Where Name =" + raw_string( 0x22 ) + usrName + raw_string( 0x22 );
	}
	usrName = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( usrName, "NTSTATUS" ) ) || !usrName){
		return ( 0 );
	}
	return usrName;
}
func wmi_user_is_userpass_required( handle, usrName ){
	if( !usrName ){
		query = "Select PasswordRequired from Win32_UserAccount";
	}
	else {
		query = "Select PasswordRequired from Win32_UserAccount Where Name =" + raw_string( 0x22 ) + usrName + raw_string( 0x22 );
	}
	usrName = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( usrName, "NTSTATUS" ) ) || !usrName){
		return ( 0 );
	}
	return usrName;
}
func wmi_user_is_user_locked( handle, usrName ){
	if( !usrName ){
		query = "Select Lockout from Win32_UserAccount";
	}
	else {
		query = "Select Lockout from Win32_UserAccount Where Name =" + raw_string( 0x22 ) + usrName + raw_string( 0x22 );
	}
	usrName = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( usrName, "NTSTATUS" ) ) || !usrName){
		return ( 0 );
	}
	return usrName;
}
func wmi_local_users( handle ){
	query = "Select * from Win32_UserAccount Where LocalAccount=true";
	LocalUserList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( LocalUserList, "NTSTATUS" ) ) || !LocalUserList){
		return ( 0 );
	}
	return LocalUserList;
}
func wmi_useraccounts_active( handle ){
	query = "Select SID from Win32_UserAccount WHERE Status='Ok'";
	usrList = wmi_query( wmi_handle: handle, query: query );
	if(( ContainsString( usrList, "NTSTATUS" ) ) || !usrList){
		set_kb_item( name: "WMI/UserAccount/Active", value: "Error" );
		return ( 0 );
	}
	set_kb_item( name: "WMI/UserAccount/Active", value: usrList );
	return usrList;
}

