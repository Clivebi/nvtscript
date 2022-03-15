if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.24017" );
	script_version( "$Revision: 14240 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2008-10-08 21:18:44 +0200 (Wed, 08 Oct 2008)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_copyright( "Copyright (C) 2007 Michel Arboi <mikhail@nessus.org>" );
	script_name( "Unmaintained Gentoo packages" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "package" );
	script_family( "Gentoo Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/pkg", "ssh/login/gentoo_maintained" );
	script_tag( name: "solution", value: "Remove or upgrade those packages." );
	script_tag( name: "summary", value: "The remote Gentoo system contains several packages or versions
  which have been marked as obsolete and have been removed from the portage tree.

  These versions are therefore unmaintained, which means that if any security flaw is found in them,
  no patch will be made available.

  In addition to this, these packages might break after a library upgrade and it will be impossible to recompile them." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("global_settings.inc.sc");
installed = get_kb_item( "ssh/login/pkg" );
maintained = get_kb_item( "ssh/login/gentoo_maintained" );
if(isnull( installed ) || isnull( maintained )){
	exit( 0 );
}
bad_l = "";
old_l = "";
obs_l = "";
maintained_v = sort( split( buffer: maintained, keep: 0 ) );
maintained = NULL;
installed_v = sort( split( buffer: installed, keep: 0 ) );
installed = NULL;
i1 = 0;
i2 = 0;
n1 = max_index( maintained_v );
n2 = max_index( installed_v );
all = 0;
bad = 0;
prev_m = maintained_v[0];
for(i2 = 0;i2 < n2;i2++){
	if(!match( string: installed_v[i2], pattern: "virtual/*" ) && !match( string: installed_v[i2], pattern: "*/-MERGING-*" ) && !match( string: installed_v[i2], pattern: "*/*.portage_lockfile" )){
		for(;i1 < n1 && maintained_v[i1] < installed_v[i2];){
			prev_m = maintained_v[i1];
			i1++;
		}
		if(maintained_v[i1] != installed_v[i2]){
			pat = "^([a-z0-9]+-[a-z0-9]+/[^0-9][a-z0-9+_-]+)-[0-9].*$";
			iv = eregmatch( string: installed_v[i2], pattern: pat, icase: 1 );
			mv = eregmatch( string: maintained_v[i1], pattern: pat, icase: 1 );
			pv = eregmatch( string: prev_m, pattern: pat, icase: 1 );
			if( !isnull( iv ) && !isnull( mv ) && !isnull( pv ) ) {
				if( iv[1] == mv[1] || iv[1] == pv[1] ) {
					old_l += installed_v[i2] + "\n";
				}
				else {
					obs_l += installed_v[i2] + "\n";
				}
			}
			else {
				debug_print( "Cannot parse ", installed_v[i2], " or ", maintained_v[i1], " or ", prev_m );
				bad_l += installed_v[i2] + "\n";
			}
			bad++;
		}
		all++;
	}
}
if(bad > 0){
	desc = "";
	if(strlen( obs_l ) > 0){
		desc = strcat( desc, "The following packages are not maintained any more:\n", obs_l, "\n" );
	}
	if(strlen( old_l ) > 0){
		desc = strcat( desc, "The following packages should be updated:\n", old_l, "\n" );
	}
	if(bad_l > 0){
		desc = strcat( desc, "The following obsolete packages were found:\n", bad_l, "\n" );
	}
	security_message( port: 0, data: desc );
}
debug_print( "Found ", bad, " obsolete packages among ", all, " packages\n" );

