func is_killbit_set( clsid ){
	if(clsid){
		if(registry_key_exists( key: "SOFTWARE\\Classes\\CLSID\\" + clsid )){
			activeKey = "SOFTWARE\\Microsoft\\Internet Explorer\\" + "ActiveX Compatibility\\" + clsid;
			killBit = registry_get_dword( key: activeKey, item: "Compatibility Flags" );
			if(killBit && ( int( killBit ) == 1024 || int( killBit ) == 67109888 )){
				return 1;
			}
			return 0;
		}
	}
	return -1;
}

