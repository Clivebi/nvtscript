if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.2416" );
	script_cve_id( "CVE-2018-1000667", "CVE-2018-10016", "CVE-2018-10316", "CVE-2018-19214", "CVE-2018-19215", "CVE-2018-19216", "CVE-2018-19755", "CVE-2018-8882" );
	script_tag( name: "creation_date", value: "2020-11-04 08:56:26 +0000 (Wed, 04 Nov 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-13 21:15:00 +0000 (Mon, 13 Jul 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for nasm (EulerOS-SA-2020-2416)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-2416" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2416" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'nasm' package(s) announced via the EulerOS-SA-2020-2416 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Netwide Assembler (NASM) 2.14rc16 has a heap-based buffer over-read in expand_mmac_params in asm/preproc.c for the special cases of the % and $ and ! characters.(CVE-2018-19216)

Netwide Assembler (NASM) 2.14rc16 has a heap-based buffer over-read in expand_mmac_params in asm/preproc.c for the special cases of the % and $ and ! characters.(CVE-2018-19215)

Netwide Assembler (NASM) 2.14rc15 has a heap-based buffer over-read in expand_mmac_params in asm/preproc.c for insufficient input.(CVE-2018-19214)

Netwide Assembler (NASM) 2.13.02rc2 has a stack-based buffer under-read in the function ieee_shr in asm/float.c via a large shift value.(CVE-2018-8882)

Netwide Assembler (NASM) 2.14rc0 has a division-by-zero vulnerability in the expr5 function in asm/eval.c via a malformed input file.(CVE-2018-10016)

Netwide Assembler (NASM) 2.14rc0 has an endless while loop in the assemble_file function of asm/nasm.c because of a globallineno integer overflow.(CVE-2018-10316)

NASM nasm-2.13.03 nasm- 2.14rc15 version 2.14rc15 and earlier contains a memory corruption (crashed) of nasm when handling a crafted file due to function assemble_file(inname, depend_ptr) at asm/nasm.c:482. vulnerability in function assemble_file(inname, depend_ptr) at asm/nasm.c:482. that can result in aborting/crash nasm program. This attack appear to be exploitable via a specially crafted asm file..(CVE-2018-1000667)

There is an illegal address access at asm/preproc.c (function: is_mmacro) in Netwide Assembler (NASM) 2.14rc16 that will cause a denial of service (out-of-bounds array access) because a certain conversion can result in a negative integer.(CVE-2018-19755)" );
	script_tag( name: "affected", value: "'nasm' package(s) on Huawei EulerOS V2.0SP9." );
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
if(release == "EULEROS-2.0SP9"){
	if(!isnull( res = isrpmvuln( pkg: "nasm", rpm: "nasm~2.13.03~5.h4.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
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
