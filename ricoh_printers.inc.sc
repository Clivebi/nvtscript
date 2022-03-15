func get_ricoh_detect_urls(  ){
	var ricoh_detect_urls;
	ricoh_detect_urls = make_array();
	ricoh_detect_urls["/machinei.asp?Lang=en-us"] = "class=\"modelName\">([^<]+)<";
	ricoh_detect_urls["/web/guest/en/websys/status/configuration.cgi"] = ">Model Name<[^:]+:<[^<]+<td nowrap>((Aficio )?[^<]+)";
	return ricoh_detect_urls;
}

