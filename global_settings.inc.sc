var report_verbosity, log_verbosity, debug_level;
report_verbosity = 1;
debug_level = 0;
log_verbosity = 1;
__gs_opt = get_kb_item( "global_settings/report_verbosity" );
if(__gs_opt){
	if( ContainsString( __gs_opt, "Normal" ) ) {
		report_verbosity = 1;
	}
	else {
		if( ContainsString( __gs_opt, "Quiet" ) ) {
			report_verbosity = 0;
		}
		else {
			if(ContainsString( __gs_opt, "Verbose" )){
				report_verbosity = 2;
			}
		}
	}
}
__gs_opt = get_kb_item( "global_settings/log_verbosity" );
if(__gs_opt){
	if( ContainsString( __gs_opt, "Normal" ) ) {
		log_verbosity = 1;
	}
	else {
		if( ContainsString( __gs_opt, "Quiet" ) ) {
			log_verbosity = 0;
		}
		else {
			if( ContainsString( __gs_opt, "Verbose" ) ) {
				log_verbosity = 2;
			}
			else {
				if(ContainsString( __gs_opt, "Debug" )){
					log_verbosity = 3;
					__gs_opt = get_kb_item( "global_settings/debug_level" );
					if(IsMatchRegexp( __gs_opt, "^[0-9]+$" )){
						debug_level = int( __gs_opt );
					}
					if(debug_level <= 0){
						debug_level = 1;
					}
				}
			}
		}
	}
}

func debug_print(msg...){
	if(debug_level < 3){
		return;
	}
	var total = "";
	for v in msg{
		total += v;
	}
	Println("DEBUG:",total);
}

func log_print(msg...){
	if(debug_level < 2){
		return;
	}
	var total = "";
	for v in msg{
		total += v;
	}
	Println("INFO:",total);
}

GLOBAL_SETTINGS_INC = 1;

