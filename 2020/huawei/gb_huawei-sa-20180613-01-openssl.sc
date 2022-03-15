if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107831" );
	script_version( "2021-08-04T02:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-04 02:01:00 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_cve_id( "CVE-2018-0739" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: OpenSSL Vulnerability in Some Huawei Products (huawei-sa-20180613-01-openssl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Constructed ASN.1 types with a recursive definition in some OpenSSL versions could eventually exceed the stack given malicious input with excessive recursion." );
	script_tag( name: "insight", value: "Constructed ASN.1 types with a recursive definition in some OpenSSL versions could eventually exceed the stack given malicious input with excessive recursion. Successful exploit could result in a Denial Of Service attack. (Vulnerability ID: HWPSIRT-2018-03073)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2018-0739.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references." );
	script_tag( name: "impact", value: "Successful exploit could result in a Denial Of Service attack." );
	script_tag( name: "affected", value: "AR3200 versions V200R008C20

  AnyOffice versions 2.5.0501.0290

  EulerOS versions V200R005C00

  FusionSphere OpenStack versions 6.5.0 6.5.RC1 6.5.RC2 V100R006C00 V100R006C10 V100R006C30

  OceanStor 5300 V3 versions V300R006C10

  OceanStor 5500 V3 versions V300R006C10

  OceanStor 5600 V3 versions V300R006C10

  OceanStor 5800 V3 versions V300R006C10

  OceanStor 6800 V3 versions V300R006C10

  OceanStor 9000 versions V300R005C00 V300R006C00 V300R006C10 V300R006C20

  OceanStor ReplicationDirector versions V200R001C00 V200R001C20

  OceanStor UDS versions V1R2C01LHWS01RC3 V1R2C01LHWS01RC6

  SMC2.0 versions V500R002C00 V600R006C00 V600R006C10

  eSpace VCN3000 versions V100R002C10 V100R002C20" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180613-01-openssl-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:ar3200_firmware",
	 "cpe:/o:huawei:anyoffice_firmware",
	 "cpe:/o:huawei:euleros_firmware",
	 "cpe:/o:huawei:fusionsphere_openstack_firmware",
	 "cpe:/o:huawei:oceanstor_5300_v3_firmware",
	 "cpe:/o:huawei:oceanstor_5500_v3_firmware",
	 "cpe:/o:huawei:oceanstor_5600_v3_firmware",
	 "cpe:/o:huawei:oceanstor_5800_v3_firmware",
	 "cpe:/o:huawei:oceanstor_6800_v3_firmware",
	 "cpe:/o:huawei:oceanstor_9000_firmware",
	 "cpe:/o:huawei:oceanstor_replicationdirector_firmware",
	 "cpe:/o:huawei:oceanstor_uds_firmware",
	 "cpe:/o:huawei:smc2.0_firmware",
	 "cpe:/o:huawei:espace_vcn3000_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if( cpe == "cpe:/o:huawei:ar3200_firmware" ){
	if(IsMatchRegexp( version, "^V200R008C20" )){
		if(!patch || version_is_less( version: patch, test_version: "V200R009C00SPC500" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
else {
	if( cpe == "cpe:/o:huawei:anyoffice_firmware" ){
		if(version == "2.5.0501.0290"){
			if(!patch || version_is_less( version: patch, test_version: "2.6.1901.0060" )){
				report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "2.6.1901.0060" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
	else {
		if( cpe == "cpe:/o:huawei:euleros_firmware" ){
			if(IsMatchRegexp( version, "^V200R005C00" )){
				if(!patch || version_is_less( version: patch, test_version: "V200R005C00SPC201" )){
					report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R005C00SPC201" );
					security_message( port: 0, data: report );
					exit( 0 );
				}
			}
		}
		else {
			if( cpe == "cpe:/o:huawei:fusionsphere_openstack_firmware" ){
				if(version == "6.5.0" || version == "6.5.RC1" || version == "6.5.RC2" || IsMatchRegexp( version, "^V100R006C00" ) || IsMatchRegexp( version, "^V100R006C10" ) || IsMatchRegexp( version, "^V100R006C30" )){
					if(!patch || version_is_less( version: patch, test_version: "6.5.0" )){
						report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "6.5.0" );
						security_message( port: 0, data: report );
						exit( 0 );
					}
				}
			}
			else {
				if( cpe == "cpe:/o:huawei:oceanstor_5300_v3_firmware" ){
					if(IsMatchRegexp( version, "^V300R006C10" )){
						if(!patch || version_is_less( version: patch, test_version: "V300R006C20" )){
							report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V300R006C20" );
							security_message( port: 0, data: report );
							exit( 0 );
						}
					}
				}
				else {
					if( cpe == "cpe:/o:huawei:oceanstor_5500_v3_firmware" ){
						if(IsMatchRegexp( version, "^V300R006C10" )){
							if(!patch || version_is_less( version: patch, test_version: "V300R006C20" )){
								report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V300R006C20" );
								security_message( port: 0, data: report );
								exit( 0 );
							}
						}
					}
					else {
						if( cpe == "cpe:/o:huawei:oceanstor_5600_v3_firmware" ){
							if(IsMatchRegexp( version, "^V300R006C10" )){
								if(!patch || version_is_less( version: patch, test_version: "V300R006C20" )){
									report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V300R006C20" );
									security_message( port: 0, data: report );
									exit( 0 );
								}
							}
						}
						else {
							if( cpe == "cpe:/o:huawei:oceanstor_5800_v3_firmware" ){
								if(IsMatchRegexp( version, "^V300R006C10" )){
									if(!patch || version_is_less( version: patch, test_version: "V300R006C20" )){
										report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V300R006C20" );
										security_message( port: 0, data: report );
										exit( 0 );
									}
								}
							}
							else {
								if( cpe == "cpe:/o:huawei:oceanstor_6800_v3_firmware" ){
									if(IsMatchRegexp( version, "^V300R006C10" )){
										if(!patch || version_is_less( version: patch, test_version: "V300R006C20" )){
											report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V300R006C20" );
											security_message( port: 0, data: report );
											exit( 0 );
										}
									}
								}
								else {
									if( cpe == "cpe:/o:huawei:oceanstor_9000_firmware" ){
										if(IsMatchRegexp( version, "^V300R005C00" ) || IsMatchRegexp( version, "^V300R006C00" ) || IsMatchRegexp( version, "^V300R006C10" ) || IsMatchRegexp( version, "^V300R006C20" )){
											if(!patch || version_is_less( version: patch, test_version: "V300R006C20SPC100" )){
												report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V300R006C20SPC100" );
												security_message( port: 0, data: report );
												exit( 0 );
											}
										}
									}
									else {
										if( cpe == "cpe:/o:huawei:oceanstor_replicationdirector_firmware" ){
											if(IsMatchRegexp( version, "^V200R001C00" ) || IsMatchRegexp( version, "^V200R001C20" )){
												if(!patch || version_is_less( version: patch, test_version: "V200R001C20SPC200" )){
													report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R001C20SPC200" );
													security_message( port: 0, data: report );
													exit( 0 );
												}
											}
										}
										else {
											if( cpe == "cpe:/o:huawei:oceanstor_uds_firmware" ){
												if(IsMatchRegexp( version, "^V1R2C01LHWS01RC3" ) || IsMatchRegexp( version, "^V1R2C01LHWS01RC6" )){
													if(!patch || version_is_less( version: patch, test_version: "V1R2C01LHWS02" )){
														report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V1R2C01LHWS02" );
														security_message( port: 0, data: report );
														exit( 0 );
													}
												}
											}
											else {
												if( cpe == "cpe:/o:huawei:smc2.0_firmware" ){
													if(IsMatchRegexp( version, "^V500R002C00" ) || IsMatchRegexp( version, "^V600R006C00" ) || IsMatchRegexp( version, "^V600R006C10" )){
														if(!patch || version_is_less( version: patch, test_version: "V600R006C10SPC700" )){
															report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V600R006C10SPC700" );
															security_message( port: 0, data: report );
															exit( 0 );
														}
													}
												}
												else {
													if(cpe == "cpe:/o:huawei:espace_vcn3000_firmware"){
														if(IsMatchRegexp( version, "^V100R002C10" ) || IsMatchRegexp( version, "^V100R002C20" )){
															if(!patch || version_is_less( version: patch, test_version: "V100R003C00" )){
																report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V100R003C00" );
																security_message( port: 0, data: report );
																exit( 0 );
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
exit( 99 );

