if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2034" );
	script_cve_id( "CVE-2016-10228" );
	script_tag( name: "creation_date", value: "2021-07-01 07:39:26 +0000 (Thu, 01 Jul 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-25 17:15:00 +0000 (Thu, 25 Feb 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for glibc (EulerOS-SA-2021-2034)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.6\\.6" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2034" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2034" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'glibc' package(s) announced via the EulerOS-SA-2021-2034 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The iconv program in the GNU C Library (aka glibc or libc6) 2.25 and earlier, when invoked with the -c option, enters an infinite loop when processing invalid multi-byte input sequences, leading to a denial of service.(CVE-2016-10228)" );
	script_tag( name: "affected", value: "'glibc' package(s) on Huawei EulerOS Virtualization 3.0.6.6." );
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
if(release == "EULEROSVIRT-3.0.6.6"){
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.17~222.h42.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-common", rpm: "glibc-common~2.17~222.h42.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-devel", rpm: "glibc-devel~2.17~222.h42.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glibc-headers", rpm: "glibc-headers~2.17~222.h42.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nscd", rpm: "nscd~2.17~222.h42.eulerosv2r7", rls: "EULEROSVIRT-3.0.6.6" ) )){
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

