CPE = "cpe:/a:wireshark:wireshark";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806029" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-6241", "CVE-2015-6242", "CVE-2015-6243", "CVE-2015-6244", "CVE-2015-6245", "CVE-2015-6246", "CVE-2015-6247", "CVE-2015-6248", "CVE-2015-6249" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-08-28 11:37:57 +0530 (Fri, 28 Aug 2015)" );
	script_name( "Wireshark Multiple Denial-of-Service Vulnerabilities-01 August15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Wireshark
  and is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in 'proto_tree_add_bytes_item' function in 'epan/proto.c' script in
  the protocol-tree implementation.

  - An error in 'wmem_block_split_free_chunk' function in
  'epan/wmem/wmem_allocator_block.c' script in the wmem block allocator in the
  memory manager.

  - An error in 'dissector-table' implementation in 'epan/packet.c' script
  which mishandles table searches for empty strings.

  - An error in 'dissect_zbee_secure' function in
  'epan/dissectors/packet-zbee-security.c' script in the ZigBee dissector.

  - Mishandling of datatype by 'epan/dissectors/packet-gsm_rlcmac.c' script in
  the GSM RLC/MAC dissector.

  - An error in 'dissect_wa_payload' function in
  'epan/dissectors/packet-waveagent.c' script in the WaveAgent dissector.

  - Improper input validation of offset value by 'dissect_openflow_tablemod_v5'
  function in 'epan/dissectors/packet-openflow_v5.c' script.

  - Invalid data length checking by 'ptvcursor_add' function in the ptvcursor
  implementation in 'epan/proto.c' script.

  - An error in 'dissect_wccp2r1_address_table_info' function in
  'epan/dissectors/packet-wccp.c' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Wireshark version 1.12.x before 1.12.7
  on Windows" );
	script_tag( name: "solution", value: "Upgrade Wireshark to version 1.12.7 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2015-24.html" );
	script_xref( name: "URL", value: "https://www.wireshark.org/security/wnpa-sec-2015-26.html" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11358" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11373" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wirversion = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: wirversion, test_version: "1.12.0", test_version2: "1.12.6" )){
	report = "Installed Version: " + wirversion + "\n" + "Fixed Version:     1.12.7 \n";
	security_message( data: report );
	exit( 0 );
}

