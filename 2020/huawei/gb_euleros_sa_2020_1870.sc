if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1870" );
	script_cve_id( "CVE-2018-19214", "CVE-2018-19216" );
	script_tag( name: "creation_date", value: "2020-08-31 07:03:54 +0000 (Mon, 31 Aug 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-13 21:15:00 +0000 (Mon, 13 Jul 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for nasm (EulerOS-SA-2020-1870)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1870" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1870" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'nasm' package(s) announced via the EulerOS-SA-2020-1870 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Netwide assembler (NASM) 2.14 rc15 in asm/preproc. C the expand_mmac_params a heap-based buffer, the buffer read is insufficient, lead to insufficient input.(CVE-2018-19214)

Netwide Assembler (NASM) before 2.13.02 has a use-after-free in detoken at asm/preproc.c(CVE-2018-19216)" );
	script_tag( name: "affected", value: "'nasm' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "nasm", rpm: "nasm~2.13.03~2.h3.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

