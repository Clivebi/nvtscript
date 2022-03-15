func get_epson_detect_urls(  ){
	var epson_detect_urls;
	epson_detect_urls = make_array();
	epson_detect_urls["/PRESENTATION/HTML/TOP/INDEX.HTML"] = "<title>([A-Z0-9-]+)( Series)?</title>";
	epson_detect_urls["/iPrinterHome.cgi"] = "Printer Model Name</td>[^>]+>\\s*([^>]+)<";
	epson_detect_urls["/PRESENTATION/ADVANCED/FORCE_PASSWORD/TOP?accsessmethod=0"] = "<title>([A-Z0-9-]+) Series</title>";
	epson_detect_urls["/Istatus.htm"] = "Model Name</B></TD>[^>]+>Epson ([^&<]+)";
	return epson_detect_urls;
}

