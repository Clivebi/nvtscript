CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814329" );
	script_version( "2019-11-11T10:19:16+0000" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-11-11 10:19:16 +0000 (Mon, 11 Nov 2019)" );
	script_tag( name: "creation_date", value: "2018-11-09 10:41:07 +0530 (Fri, 09 Nov 2018)" );
	script_name( "Oracle VirtualBox Guest-to-Host Escape E1000 Privilege Escalation Vulnerability (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Oracle VirtualBox
  and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the Intel PRO/1000 MT
  Desktop (82540EM) network adapter in Network Address Translation (NAT) mode
  called the E1000." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  with root/administrator privileges in a guest to escape to a host ring3. Then the
  attacker can use existing techniques to escalate privileges to ring 0 via
  /dev/vboxdrv" );
	script_tag( name: "affected", value: "Oracle VirtualBox versions 5.2.20 and
  before on Linux." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://github.com/MorteNoir1/virtualbox_e1000_0day" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "secpod_sun_virtualbox_detect_lin.sc" );
	script_mandatory_keys( "Sun/VirtualBox/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
appVer = infos["version"];
appPath = infos["location"];
if(IsMatchRegexp( appVer, "^5\\.2" )){
	if(version_is_less_equal( version: appVer, test_version: "5.2.20.125813" )){
		report = report_fixed_ver( installed_version: appVer, fixed_version: "None", install_path: appPath );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

