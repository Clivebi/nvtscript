func get_toshiba_detect_urls(  ){
	var toshiba_detect_urls;
	toshiba_detect_urls = make_array();
	toshiba_detect_urls["/TopAccess/Device/Device.htm"] = ">Copier Model.*>TOSHIBA [^&]+";
	toshiba_detect_urls["/Device/Device.html"] = "id=\"DeviceCopierModel\"";
	toshiba_detect_urls["/"] = "<title>TOSHIBA (e-STUDIO[^<]+)</title>";
	return toshiba_detect_urls;
}

