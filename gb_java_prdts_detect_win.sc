if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800383" );
	script_version( "2021-08-11T13:42:58+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-11 13:42:58 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Sun/Oracle Java Products Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Java Products.

  The script logs in via smb, searches for Java Products in the registry and
  gets the version from 'Version' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	adkeylist = make_list( "SOFTWARE\\JavaSoft\\Java Runtime Environment\\",
		 "SOFTWARE\\JavaSoft\\JRE\\" );
}
else {
	if(ContainsString( osArch, "x64" )){
		adkeylist = make_list( "SOFTWARE\\JavaSoft\\Java Runtime Environment\\",
			 "SOFTWARE\\JavaSoft\\JRE\\",
			 "SOFTWARE\\Wow6432Node\\JavaSoft\\Java Runtime Environment\\",
			 "SOFTWARE\\Wow6432Node\\JavaSoft\\JRE\\" );
	}
}
for jreKey in adkeylist {
	if(registry_key_exists( key: jreKey )){
		keys = registry_enum_keys( key: jreKey );
		for item in keys {
			if( ContainsString( jreKey, "JRE" ) && IsMatchRegexp( item, "^(9|10|11|12|15|16)" ) ){
				pattern = "([0-9.]+)";
				flagjre9plus = TRUE;
			}
			else {
				pattern = "([0-9]+\\.[0-9]+\\.[0-9._]+)";
			}
			jreVer = eregmatch( pattern: pattern, string: item );
			if(jreVer[1]){
				JreTmpkey = jreKey + "\\\\" + jreVer[1];
				path = registry_get_sz( key: JreTmpkey, item: "JavaHome" );
				if(!path){
					path = "Could not find the install path from registry";
				}
				if(!isnull( jreVer[1] )){
					set_kb_item( name: "Sun/Java/JRE/Win/Ver", value: jreVer[1] );
					set_kb_item( name: "Sun/Java/JDK_or_JRE/Win/installed", value: TRUE );
					set_kb_item( name: "Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value: TRUE );
					if( flagjre9plus ){
						jreVer_or = jreVer[1];
						flagjre9plus = FALSE;
					}
					else {
						jrVer = ereg_replace( pattern: "_|-", string: jreVer[1], replace: "." );
						jreVer1 = eregmatch( pattern: "([0-9]+\\.[0-9]+\\.[0-9]+)(\\.([0-9]+))?", string: jrVer );
						if( jreVer1[1] && jreVer1[3] ){
							jreVer_or = jreVer1[1] + ":update_" + jreVer1[3];
						}
						else {
							if(jreVer1[1]){
								jreVer_or = jreVer1[1];
							}
						}
					}
					if( version_is_less( version: jrVer, test_version: "1.4.2.38" ) || version_in_range( version: jrVer, test_version: "1.5", test_version2: "1.5.0.33" ) || version_in_range( version: jrVer, test_version: "1.6", test_version2: "1.6.0.18" ) ){
						java_name = "Sun Java JRE 32-bit";
						cpe = build_cpe( value: jreVer_or, exp: "^([:a-z0-9._]+)", base: "cpe:/a:sun:jre:" );
						if(isnull( cpe )){
							cpe = "cpe:/a:sun:jre";
						}
					}
					else {
						java_name = "Oracle Java JRE 32-bit";
						cpe = build_cpe( value: jreVer_or, exp: "^([:a-z0-9._]+)", base: "cpe:/a:oracle:jre:" );
						if(isnull( cpe )){
							cpe = "cpe:/a:oracle:jre";
						}
					}
					if(!isnull( jreVer[1] ) && ContainsString( osArch, "x64" ) && !ContainsString( jreKey, "Wow6432Node" )){
						set_kb_item( name: "Sun/Java64/JRE64/Win/Ver", value: jreVer[1] );
						if( version_is_less( version: jrVer, test_version: "1.4.2.38" ) || version_in_range( version: jrVer, test_version: "1.5", test_version2: "1.5.0.33" ) || version_in_range( version: jrVer, test_version: "1.6", test_version2: "1.6.0.18" ) ){
							java_name = "Sun Java JRE 64-bit";
							cpe = build_cpe( value: jreVer_or, exp: "^([:a-z0-9._]+)", base: "cpe:/a:sun:jre:x64:" );
							if(isnull( cpe )){
								cpe = "cpe:/a:sun:jre:x64";
							}
						}
						else {
							java_name = "Oracle Java JRE 64-bit";
							cpe = build_cpe( value: jreVer_or, exp: "^([:a-z0-9._]+)", base: "cpe:/a:oracle:jre:x64:" );
							if(isnull( cpe )){
								cpe = "cpe:/a:oracle:jre:x64";
							}
						}
					}
					tmp_location = tolower( path );
					tmp_location = ereg_replace( pattern: "\\\\$", string: tmp_location, replace: "" );
					set_kb_item( name: "Java/Win/InstallLocations", value: tmp_location );
					set_kb_item( name: "Java/Win/InstallLocations", value: tmp_location + "\\bin" );
					register_and_report_cpe( app: java_name, ver: jreVer[1], cpename: cpe, insloc: path );
				}
			}
		}
	}
}
if( ContainsString( osArch, "x86" ) ){
	adkeylist = make_list( "SOFTWARE\\JavaSoft\\Java Development Kit",
		 "SOFTWARE\\JavaSoft\\JDK" );
}
else {
	if(ContainsString( osArch, "x64" )){
		adkeylist = make_list( "SOFTWARE\\JavaSoft\\Java Development Kit",
			 "SOFTWARE\\JavaSoft\\JDK",
			 "SOFTWARE\\Wow6432Node\\JavaSoft\\Java Development Kit",
			 "SOFTWARE\\Wow6432Node\\JavaSoft\\JDK" );
	}
}
for jdkKey in adkeylist {
	if(registry_key_exists( key: jdkKey )){
		keys = registry_enum_keys( key: jdkKey );
		for item in keys {
			if( ContainsString( jdkKey, "JDK" ) && IsMatchRegexp( item, "^(9|10|11|12|15|16)" ) ){
				pattern = "([0-9.]+)";
				flagjdk9plus = TRUE;
			}
			else {
				pattern = "([0-9]+\\.[0-9]+\\.[0-9._]+)";
			}
			jdkVer = eregmatch( pattern: pattern, string: item );
			if(jdkVer[1]){
				JdkTmpkey = jdkKey + "\\\\" + jdkVer[1];
				if( !registry_key_exists( key: JdkTmpkey ) ){
					path = "Could not find the install path from registry";
				}
				else {
					path = registry_get_sz( key: JdkTmpkey, item: "JavaHome" );
					if(!path){
						path = "Could not find the install path from registry";
					}
				}
				if(!isnull( jdkVer[1] )){
					set_kb_item( name: "Sun/Java/JDK/Win/Ver", value: jdkVer[1] );
					set_kb_item( name: "Sun/Java/JDK_or_JRE/Win/installed", value: TRUE );
					set_kb_item( name: "Sun/Java/JDK_or_JRE/Win_or_Linux/installed", value: TRUE );
					if( flagjdk9plus ){
						jdkVer_or = jdkVer[1];
						flagjdk9plus = FALSE;
					}
					else {
						jdVer = ereg_replace( pattern: "_|-", string: jdkVer[1], replace: "." );
						jdkVer1 = eregmatch( pattern: "([0-9]+\\.[0-9]+\\.[0-9]+)\\.([0-9]+)", string: jdVer );
						jdkVer_or = jdkVer1[1] + ":update_" + jdkVer1[2];
					}
					if( version_is_less( version: jdVer, test_version: "1.4.2.38" ) || version_in_range( version: jdVer, test_version: "1.5", test_version2: "1.5.0.33" ) || version_in_range( version: jdVer, test_version: "1.6", test_version2: "1.6.0.18" ) ){
						jdk_name = "Sun Java JDK 32-bit";
						cpe = build_cpe( value: jdkVer_or, exp: "^([:a-z0-9._]+)", base: "cpe:/a:sun:jdk:" );
						if(isnull( cpe )){
							cpe = "cpe:/a:sun:jdk";
						}
					}
					else {
						jdk_name = "Oracle Java JDK 32-bit";
						cpe = build_cpe( value: jdkVer_or, exp: "^([:a-z0-9._]+)", base: "cpe:/a:oracle:jdk:" );
						if(isnull( cpe )){
							cpe = "cpe:/a:oracle:jdk";
						}
					}
					if(!isnull( jdkVer[1] ) && ContainsString( osArch, "x64" ) && !ContainsString( jdkKey, "Wow6432Node" )){
						set_kb_item( name: "Sun/Java64/JDK64/Win/Ver", value: jdkVer[1] );
						if( version_is_less( version: jdVer, test_version: "1.4.2.38" ) || version_in_range( version: jdVer, test_version: "1.5", test_version2: "1.5.0.33" ) || version_in_range( version: jdVer, test_version: "1.6", test_version2: "1.6.0.18" ) ){
							jdk_name = "Sun Java JDK 64-bit";
							cpe = build_cpe( value: jdkVer_or, exp: "^([:a-z0-9._]+)", base: "cpe:/a:sun:jdk:x64:" );
							if(isnull( cpe )){
								cpe = "cpe:/a:sun:jdk:x64";
							}
						}
						else {
							jdk_name = "Oracle Java JDK 64-bit";
							cpe = build_cpe( value: jdkVer_or, exp: "^([:a-z0-9._]+)", base: "cpe:/a:oracle:jdk:x64:" );
							if(isnull( cpe )){
								cpe = "cpe:/a:oracle:jdk:x64";
							}
						}
					}
					tmp_location = tolower( path );
					tmp_location = ereg_replace( pattern: "\\\\$", string: tmp_location, replace: "" );
					set_kb_item( name: "Java/Win/InstallLocations", value: tmp_location );
					set_kb_item( name: "Java/Win/InstallLocations", value: tmp_location + "\\bin" );
					register_and_report_cpe( app: jdk_name, ver: jdkVer[1], cpename: cpe, insloc: path );
				}
			}
		}
	}
}
exit( 0 );

