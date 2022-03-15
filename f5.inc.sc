var __f5_valid_products, __f5_kb_hotfix;
func f5_hotfix_from_kb(  ){
	var hotfix;
	if( !isnull( __f5_kb_hotfix ) ){
		return __f5_kb_hotfix;
	}
	else {
		if( !hotfix = get_kb_item( "f5/big_ip/hotfix" ) ){
			hotfix = int( 0 );
		}
		else {
			hotfix = int( hotfix );
			__f5_kb_hotfix = hotfix;
		}
	}
	return hotfix;
}
func f5_valid_products(  ){
	var valid_products;
	if( !isnull( __f5_valid_products ) ){
		return __f5_valid_products;
	}
	else {
		valid_products = make_list( "LTM",
			 "AAM",
			 "AFM",
			 "APM",
			 "ASM",
			 "GTM",
			 "PEM",
			 "PSM",
			 "WOM",
			 "AVR",
			 "WAM",
			 "LC" );
		__f5_valid_products = valid_products;
		return valid_products;
	}
}
func f5_is_vulnerable( ca, version ){
	var ca, version;
	var active_modules, is_vulnerable, _product, av_array, affected, unaffected, af, _a, affected_modules, unaffected_modules;
	if(!is_array( ca )){
		return;
	}
	if(!version){
		return;
	}
	if(!active_modules = get_kb_item( "f5/big_ip/active_modules" )){
		return;
	}
	is_vulnerable = FALSE;
	for _product in keys( ca ) {
		if(!in_array( search: _product, array: f5_valid_products() )){
			continue;
		}
		if(!ContainsString( active_modules, _product )){
			continue;
		}
		av_array = ca[_product];
		affected = av_array["affected"];
		unaffected = av_array["unaffected"];
		if(!strlen( affected )){
			return;
		}
		if(strlen( unaffected )){
			if(f5_is_unaffected( version: version, unaffected: unaffected )){
				return;
			}
		}
		af = split( buffer: affected, sep: ";", keep: FALSE );
		if(!is_array( af )){
			continue;
		}
		for _a in af {
			if(f5_check_version( a: _a, version: version )){
				affected_modules += "\t" + _product + " (" + f5_clean_version( v: _a ) + ")\n";
				unaffected_modules += "\t" + _product + ": " + f5_clean_version( v: unaffected ) + "\n";
				is_vulnerable = TRUE;
				break;
			}
		}
	}
	if(is_vulnerable){
		return f5_build_report( affected_modules: affected_modules, unaffected_modules: unaffected_modules, version: version );
	}
	return;
}
func f5_is_unaffected( version, unaffected ){
	var version, unaffected;
	var ua, _uav, v_h, c_version, c_hotfix, both, first, last, first_hotfix, last_hotfix, major, pattern;
	if(!version){
		return;
	}
	if(!unaffected){
		return;
	}
	ua = split( buffer: unaffected, sep: ";", keep: FALSE );
	if(!is_array( ua )){
		return;
	}
	for _uav in ua {
		if( ContainsString( _uav, "_HF" ) && !ContainsString( _uav, "-" ) ){
			v_h = eregmatch( pattern: "([0-9.]+)_HF([0-9]+)", string: _uav );
			c_version = v_h[1];
			c_hotfix = v_h[2];
			if(isnull( c_version ) || isnull( c_hotfix )){
				return;
			}
			if(version == c_version){
				if(f5_hotfix_from_kb() >= int( c_hotfix )){
					return TRUE;
				}
			}
		}
		else {
			if( ContainsString( _uav, "-" ) ){
				both = split( buffer: _uav, sep: "-", keep: FALSE );
				if(isnull( both[0] ) || isnull( both[1] )){
					return;
				}
				first = both[0];
				last = both[1];
				first_hotfix = int( 0 );
				last_hotfix = int( 0 );
				if(ContainsString( first, "_HF" )){
					v_h = eregmatch( pattern: "([0-9.]+)_HF([0-9]+)", string: first );
					if(!is_array( v_h )){
						return;
					}
					first = v_h[1];
					first_hotfix = v_h[2];
				}
				if(ContainsString( last, "_HF" )){
					v_h = eregmatch( pattern: "([0-9.]+)_HF([0-9]+)", string: last );
					if(!is_array( v_h )){
						return;
					}
					last = v_h[1];
					last_hotfix = v_h[2];
				}
				first += "." + first_hotfix;
				last += "." + last_hotfix;
				if(version_in_range( version: version + "." + f5_hotfix_from_kb(), test_version: first, test_version2: last )){
					return TRUE;
				}
			}
			else {
				major = split( buffer: _uav, sep: ".", keep: FALSE );
				pattern = "^" + major[0] + "\\.";
				if(egrep( pattern: pattern, string: version ) && version_is_greater_equal( version: version, test_version: _uav )){
					return TRUE;
				}
			}
		}
	}
	return;
}
func f5_check_version( a, version ){
	var a, version;
	var v, c_version, hotfixes, low_hotfix, hi_hotfix, both, b, v_high, v_low, hi, low, fvh, first_vuln_hotfix, v_h, c_hotfix, first, last, pattern;
	if(IsMatchRegexp( a, "[0-9.]+_HF([0-9]+)-HF([0-9]+)" )){
		v = eregmatch( pattern: "([0-9.]+)_HF", string: a );
		if(isnull( v[1] )){
			return;
		}
		c_version = v[1];
		hotfixes = eregmatch( pattern: "[0-9.]+_HF([0-9]+)-HF([0-9]+)", string: a );
		if(isnull( hotfixes[1] ) || isnull( hotfixes[2] )){
			return;
		}
		low_hotfix = hotfixes[1];
		hi_hotfix = hotfixes[2];
		if(version == c_version){
			if(f5_hotfix_from_kb() < int( low_hotfix )){
				return;
			}
			if(f5_hotfix_from_kb() <= int( hi_hotfix )){
				return TRUE;
			}
		}
		return;
	}
	if( ContainsString( a, "_HF" ) ){
		if(ContainsString( a, "-" )){
			both = split( buffer: a, sep: "-", keep: FALSE );
			if(isnull( both[1] )){
				return;
			}
			a = both[1];
			b = both[0];
			v_high = eregmatch( pattern: "([0-9.]+)(_HF)?", string: a );
			v_low = eregmatch( pattern: "([0-9.]+)(_HF)?", string: b );
			hi = v_high[1];
			low = v_low[1];
			if(hi != low){
				if(version_in_range( version: version, test_version: low, test_version2: hi )){
					if(version == hi){
						fvh = eregmatch( pattern: "([0-9.]+)_HF([0-9]+)", string: a );
						if(!isnull( fvh[2] )){
							if(f5_hotfix_from_kb() > int( fvh[2] )){
								return;
							}
						}
					}
					if(version == low){
						fvh = eregmatch( pattern: "([0-9.]+)_HF([0-9]+)", string: b );
						if(!isnull( fvh[2] )){
							if(f5_hotfix_from_kb() < int( fvh[2] )){
								return;
							}
						}
					}
					return TRUE;
				}
			}
			if(ContainsString( b, "_HF" )){
				fvh = eregmatch( pattern: "([0-9.]+)_HF([0-9]+)", string: b );
				if(!isnull( fvh[2] )){
					first_vuln_hotfix = fvh[2];
				}
			}
		}
		v_h = eregmatch( pattern: "([0-9.]+)_HF([0-9]+)", string: a );
		c_version = v_h[1];
		c_hotfix = v_h[2];
		if(isnull( c_version ) || isnull( c_hotfix )){
			return;
		}
		if(c_version == version){
			if(first_vuln_hotfix){
				if(f5_hotfix_from_kb() < int( first_vuln_hotfix )){
					return;
				}
			}
			if(f5_hotfix_from_kb() <= int( c_hotfix )){
				return TRUE;
			}
		}
		return;
	}
	else {
		if( ContainsString( a, "-" ) ){
			both = split( buffer: a, sep: "-", keep: FALSE );
			if(isnull( both[0] ) || isnull( both[1] )){
				return;
			}
			first = both[0];
			last = both[1];
			if(version_in_range( version: version, test_version: first, test_version2: last )){
				return TRUE;
			}
			last = ereg_replace( pattern: "\\.", string: last, replace: "\\." );
			pattern = "^" + last;
			if(egrep( pattern: pattern, string: version )){
				return TRUE;
			}
		}
		else {
			if(version == a){
				return TRUE;
			}
		}
	}
	return;
}
func f5_clean_version( v ){
	var v, ret;
	ret = str_replace( string: v, find: ";", replace: ", " );
	ret = str_replace( string: ret, find: "_HF", replace: " HF" );
	ret = str_replace( string: ret, find: "-", replace: " - " );
	ret = ereg_replace( string: ret, pattern: ", $", replace: "" );
	return ret;
}
func f5_build_report( affected_modules, unaffected_modules, version ){
	var affected_modules, unaffected_modules, version;
	var report, hotfix;
	report = "Installed Version: " + version + "\n";
	hotfix = f5_hotfix_from_kb();
	if(hotfix){
		report += "Installed Hotfix: " + hotfix;
	}
	report += "\n\nAffected Modules:\n\n" + affected_modules + "\n";
	report += "\nUnaffected Modules:\n\n" + unaffected_modules + "\n";
	return report;
}

