if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1053" );
	script_cve_id( "CVE-2017-13748", "CVE-2017-14132", "CVE-2018-19539", "CVE-2018-19542", "CVE-2018-9055" );
	script_tag( name: "creation_date", value: "2020-01-23 13:18:19 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-05 14:53:00 +0000 (Fri, 05 Feb 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for jasper (EulerOS-SA-2020-1053)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.5\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1053" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1053" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'jasper' package(s) announced via the EulerOS-SA-2020-1053 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "JasPer 2.0.14 allows denial of service via a reachable assertion in the function jpc_firstone in libjasper/jpc/jpc_math.c.(CVE-2018-9055)

An issue was discovered in JasPer 2.0.14. There is a NULL pointer dereference in the function jp2_decode in libjasper/jp2/jp2_dec.c, leading to a denial of service.(CVE-2018-19542)

An issue was discovered in JasPer 2.0.14. There is an access violation in the function jas_image_readcmpt in libjasper/base/jas_image.c, leading to a denial of service.(CVE-2018-19539)

JasPer 2.0.13 allows remote attackers to cause a denial of service (heap-based buffer over-read and application crash) via a crafted image, related to the jas_image_ishomosamp function in libjasper/base/jas_image.c.(CVE-2017-14132)

There are lots of memory leaks in JasPer 2.0.12, triggered in the function jas_strdup() in base/jas_string.c, that will lead to a remote denial of service attack.(CVE-2017-13748)" );
	script_tag( name: "affected", value: "'jasper' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.5.0." );
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
if(release == "EULEROSVIRTARM64-3.0.5.0"){
	if(!isnull( res = isrpmvuln( pkg: "jasper-libs", rpm: "jasper-libs~2.0.14~7.h3.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.5.0" ) )){
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

