if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2523" );
	script_cve_id( "CVE-2019-7148" );
	script_tag( name: "creation_date", value: "2020-01-23 13:03:35 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for elfutils (EulerOS-SA-2019-2523)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2523" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2523" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'elfutils' package(s) announced via the EulerOS-SA-2019-2523 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "**DISPUTED** An attempted excessive memory allocation was discovered in the function read_long_names in elf_begin.c in libelf in elfutils 0.174. Remote attackers could leverage this vulnerability to cause a denial-of-service via crafted elf input, which leads to an out-of-memory exception. NOTE: The maintainers believe this is not a real issue, but instead a 'warning caused by ASAN because the allocation is big. By setting ASAN_OPTIONS=allocator_may_return_null=1 and running the reproducer, nothing happens.'(CVE-2019-7148)" );
	script_tag( name: "affected", value: "'elfutils' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "elfutils", rpm: "elfutils~0.170~4.h5.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "elfutils-default-yama-scope", rpm: "elfutils-default-yama-scope~0.170~4.h5.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "elfutils-devel", rpm: "elfutils-devel~0.170~4.h5.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "elfutils-libelf", rpm: "elfutils-libelf~0.170~4.h5.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "elfutils-libelf-devel", rpm: "elfutils-libelf-devel~0.170~4.h5.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "elfutils-libs", rpm: "elfutils-libs~0.170~4.h5.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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
