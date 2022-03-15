if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1044" );
	script_cve_id( "CVE-2018-19139", "CVE-2018-19539", "CVE-2018-19540", "CVE-2018-19541", "CVE-2018-19542" );
	script_tag( name: "creation_date", value: "2021-01-08 21:54:29 +0000 (Fri, 08 Jan 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-29 22:15:00 +0000 (Fri, 29 Jan 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for jasker (EulerOS-SA-2021-1044)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.2\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1044" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1044" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'jasker' package(s) announced via the EulerOS-SA-2021-1044 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in JasPer 2.0.14. There is an access violation in the function jas_image_readcmpt in libjasper/base/jas_image.c, leading to a denial of service.(CVE-2018-19539)

An issue was discovered in JasPer 2.0.14. There is a heap-based buffer overflow of size 1 in the function jas_icctxtdesc_input in libjasper/base/jas_icc.c.(CVE-2018-19540)

An issue was discovered in JasPer 2.0.14. There is a NULL pointer dereference in the function jp2_decode in libjasper/jp2/jp2_dec.c, leading to a denial of service.(CVE-2018-19542)

An issue has been found in JasPer 2.0.14. There is a memory leak in jas_malloc.c when called from jpc_unk_getparms in jpc_cs.c.(CVE-2018-19139)

An issue was discovered in JasPer 2.0.14. There is a heap-based buffer over-read of size 8 in the function jas_image_depalettize in libjasper/base/jas_image.c.(CVE-2018-19541)" );
	script_tag( name: "affected", value: "'jasker' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "jasper", rpm: "jasper~1.900.1~33.h8", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-debuginfo", rpm: "jasper-debuginfo~1.900.1~33.h8", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-devel", rpm: "jasper-devel~1.900.1~33.h8", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-libs", rpm: "jasper-libs~1.900.1~33.h8", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "jasper-utils", rpm: "jasper-utils~1.900.1~33.h8", rls: "EULEROSVIRTARM64-3.0.2.0" ) )){
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

