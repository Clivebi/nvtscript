if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2236" );
	script_cve_id( "CVE-2018-16548", "CVE-2018-6541", "CVE-2018-7725", "CVE-2018-7726", "CVE-2018-7727" );
	script_tag( name: "creation_date", value: "2020-01-23 12:42:24 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-28 15:15:00 +0000 (Sun, 28 Jun 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for zziplib (EulerOS-SA-2019-2236)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2236" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2236" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'zziplib' package(s) announced via the EulerOS-SA-2019-2236 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in ZZIPlib 0.13.68. An invalid memory address dereference was discovered in zzip_disk_fread in mmapped.c. The vulnerability causes an application crash, which leads to denial of service.(CVE-2018-7725 )

An issue was discovered in ZZIPlib 0.13.68. There is a bus error caused by the __zzip_parse_root_directory function of zip.c. Attackers could leverage this vulnerability to cause a denial of service via a crafted zip file.(CVE-2018-7726)

An issue was discovered in ZZIPlib 0.13.68. There is a memory leak triggered in the function zzip_mem_disk_new in memdisk.c, which will lead to a denial of service attack.(CVE-2018-7727)

In ZZIPlib 0.13.67, there is a bus error caused by loading of a misaligned address (when handling disk64_trailer local entries) in __zzip_fetch_disk_trailer (zzip/zip.c). Remote attackers could leverage this vulnerability to cause a denial of service via a crafted zip file.(CVE-2018-6541)

An issue was discovered in ZZIPlib through 0.13.69. There is a memory leak triggered in the function __zzip_parse_root_directory in zip.c, which will lead to a denial of service attack.(CVE-2018-16548)" );
	script_tag( name: "affected", value: "'zziplib' package(s) on Huawei EulerOS V2.0SP5." );
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
if(release == "EULEROS-2.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "zziplib", rpm: "zziplib~0.13.62~11.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

