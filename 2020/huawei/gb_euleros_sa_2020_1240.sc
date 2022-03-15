if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1240" );
	script_cve_id( "CVE-2016-7976", "CVE-2016-9601", "CVE-2017-7885", "CVE-2017-7975", "CVE-2017-7976", "CVE-2017-9216", "CVE-2018-11645", "CVE-2019-14811", "CVE-2019-14812", "CVE-2019-14813", "CVE-2019-14817" );
	script_tag( name: "creation_date", value: "2020-03-13 07:17:28 +0000 (Fri, 13 Mar 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-16 13:20:00 +0000 (Fri, 16 Oct 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for ghostscript (EulerOS-SA-2020-1240)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1240" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1240" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ghostscript' package(s) announced via the EulerOS-SA-2020-1240 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The PS Interpreter in Ghostscript 9.18 and 9.20 allows remote attackers to execute arbitrary code via crafted userparams.(CVE-2016-7976)

psi/zfile.c in Artifex Ghostscript before 9.21rc1 permits the status command even if -dSAFER is used, which might allow remote attackers to determine the existence and size of arbitrary files, a similar issue to CVE-2016-7977.(CVE-2018-11645)

A flaw was found in, ghostscript versions prior to 9.50, in the .pdfexectoken and other procedures where it did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A specially crafted PostScript file could disable security protection and then have access to the file system, or execute arbitrary commands.(CVE-2019-14817)

A flaw was found in ghostscript, versions 9.x before 9.50, in the setsystemparams procedure where it did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A specially crafted PostScript file could disable security protection and then have access to the file system, or execute arbitrary commands.(CVE-2019-14813)

A flaw was found in all ghostscript versions 9.x before 9.50, in the .setuserparams2 procedure where it did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A specially crafted PostScript file could disable security protection and then have access to the file system, or execute arbitrary commands.(CVE-2019-14812)

A flaw was found in, ghostscript versions prior to 9.50, in the .pdf_hook_DSC_Creator procedure where it did not properly secure its privileged calls, enabling scripts to bypass `-dSAFER` restrictions. A specially crafted PostScript file could disable security protection and then have access to the file system, or execute arbitrary commands.(CVE-2019-14811)

libjbig2dec.a in Artifex jbig2dec 0.13, as used in MuPDF and Ghostscript, has a NULL pointer dereference in the jbig2_huffman_get function in jbig2_huffman.c. For example, the jbig2dec utility will crash (segmentation fault) when parsing an invalid file.(CVE-2017-9216)

Artifex jbig2dec 0.13, as used in Ghostscript, allows out-of-bounds writes because of an integer overflow in the jbig2_build_huffman_table function in jbig2_huffman.c during operations on a crafted JBIG2 file, leading to a denial of service (application crash) or possibly execution of arbitrary code.(CVE-2017-7975)

Artifex jbig2dec 0.13 has a heap-based buffer over-read leading to denial of service (application crash) or disclosure of sensitive information from process memory, because of an integer overflow in the jbig2_decode_symbol_dict function in jbig2_symbol_dict.c in libjbig2dec.a during operation on a crafted .jb2 file.(CVE-2017-7885)

Artifex jbig2dec 0.13 allows out-of-bounds writes and reads because of an integer overflow in the jbig2_image_compose function in jbig2_image.c during operations on a crafted ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'ghostscript' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
if(release == "EULEROSVIRTARM64-3.0.2.0"){
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.07~31.6.h10", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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

