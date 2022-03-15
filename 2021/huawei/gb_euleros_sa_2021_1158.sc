if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1158" );
	script_cve_id( "CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572" );
	script_tag( name: "creation_date", value: "2021-02-02 07:44:56 +0000 (Tue, 02 Feb 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-12 04:15:00 +0000 (Sat, 12 Dec 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for opensc (EulerOS-SA-2021-1158)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1158" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1158" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'opensc' package(s) announced via the EulerOS-SA-2021-1158 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Oberthur smart card software driver in OpenSC before 0.21.0-rc1 has a heap-based buffer overflow in sc_oberthur_read_file.(CVE-2020-26570)

The gemsafe GPK smart card software driver in OpenSC before 0.21.0-rc1 has a stack-based buffer overflow in sc_pkcs15emu_gemsafeGPK_init.(CVE-2020-26571)

The TCOS smart card software driver in OpenSC before 0.21.0-rc1 has a stack-based buffer overflow in tcos_decipher.(CVE-2020-26572)" );
	script_tag( name: "affected", value: "'opensc' package(s) on Huawei EulerOS V2.0SP8." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "EULEROS-2.0SP8"){
	if(!isnull( res = isrpmvuln( pkg: "opensc", rpm: "opensc~0.19.0~1.h4.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

