__pkg_match = FALSE;
func ispkgvuln( pkg, unaffected, vulnerable ){
	var pkg, unaffected, vulnerable;
	var kbrls, pkgs, narrowed, list, _package, _vver, vvercomp, rc, res, sub, report;
	kbrls = get_kb_item( "ssh/login/release" );
	if(kbrls != "GENTOO"){
		return NULL;
	}
	pkgs = get_kb_item( "ssh/login/pkg" );
	if(!pkgs){
		return NULL;
	}
	narrowed = egrep( pattern: "^" + pkg + "-[0-9]", string: pkgs );
	if(!narrowed){
		return NULL;
	}
	list = split( buffer: narrowed, sep: "\n", keep: FALSE );
	__pkg_match = TRUE;
	for _package in list {
		for _vver in vulnerable {
			vvercomp = split( buffer: _vver, sep: " ", keep: FALSE );
			rc = revcomp( a: _package, b: pkg + "-" + vvercomp[1] );
			res = 0;
			if(vvercomp[0] == "lt" && rc < 0){
				res = 1;
			}
			if(vvercomp[0] == "le" && rc <= 0){
				res = 1;
			}
			if(vvercomp[0] == "gt" && rc > 0){
				res = 1;
			}
			if(vvercomp[0] == "ge" && rc >= 0){
				res = 1;
			}
			if(vvercomp[0] == "eq" && rc == 0){
				res = 1;
			}
		}
		if(res == 0){
			return NULL;
		}
		for _vver in unaffected {
			vvercomp = split( buffer: _vver, sep: " ", keep: FALSE );
			rc = revcomp( a: _package, b: pkg + "-" + vvercomp[1] );
			if(vvercomp[0] == "lt" && rc < 0){
				res = 0;
			}
			if(vvercomp[0] == "le" && rc <= 0){
				res = 0;
			}
			if(vvercomp[0] == "gt" && rc > 0){
				res = 0;
			}
			if(vvercomp[0] == "ge" && rc >= 0){
				res = 0;
			}
			if(vvercomp[0] == "eq" && rc == 0){
				res = 0;
			}
			if(( vvercomp[0] == "rge" && rc >= 0 ) || ( vvercomp[0] == "rgt" && rc > 0 )){
				sub = eregmatch( pattern: "(.*-r)[0-9]+$", string: vvercomp[1] );
				if(!sub){
					sub = vvercomp[1];
				}
				if(ContainsString( _package, sub )){
					res = 0;
				}
			}
		}
		if(res == 1){
			report = "Package " + _package + " is installed which is known to be vulnerable.\n";
			return report;
		}
	}
	return NULL;
}

