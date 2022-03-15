if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150300" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-21 12:53:49 +0000 (Tue, 21 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configuring Rate Limiting for ARP Packets (Deprecated)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "This NVT has been replaced by the following NVTs:

  - 'Huawei Data Communication: Configuring ARP Packet Rate Limiting' (OID: 1.3.6.1.4.1.25623.1.0.150258)" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

