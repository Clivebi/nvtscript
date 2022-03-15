CPE = "cpe:/a:videolan:vlc_media_player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802420" );
	script_version( "2019-05-17T10:45:27+0000" );
	script_cve_id( "CVE-2012-0904" );
	script_bugtraq_id( 51255 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "creation_date", value: "2012-01-23 15:30:49 +0530 (Mon, 23 Jan 2012)" );
	script_name( "VLC Media Player '.amr' File Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72085" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18309/" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2012-01/0033.html" );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_vlc_media_player_detect_win.sc" );
	script_mandatory_keys( "VLCPlayer/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to crash the
affected application, denying service to legitimate users." );
	script_tag( name: "affected", value: "VLC media player version prior to 1.1.11 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an access violation error, when opening a
specially-crafted '.amr' file, which allows remote attacker to cause the
application to crash." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with VLC Media Player and is prone to denial
of service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_equal( version: vers, test_version: "1.1.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

