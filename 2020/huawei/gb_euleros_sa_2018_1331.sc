if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1331" );
	script_cve_id( "CVE-2017-11671" );
	script_tag( name: "creation_date", value: "2020-01-23 11:22:00 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-12 01:29:00 +0000 (Thu, 12 Apr 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for gcc (EulerOS-SA-2018-1331)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1331" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1331" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'gcc' package(s) announced via the EulerOS-SA-2018-1331 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Under certain circumstances, the ix86_expand_builtin function in i386.c in GNU Compiler Collection (GCC) version 4.6, 4.7, 4.8, 4.9, 5 before 5.5, and 6 before 6.4 will generate instruction sequences that clobber the status flag of the RDRAND and RDSEED intrinsics before it can be read, potentially causing failures of these instructions to go unreported. This could potentially lead to less randomness in random number generation.(CVE-2017-11671)" );
	script_tag( name: "affected", value: "'gcc' package(s) on Huawei EulerOS Virtualization 2.5.0." );
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
if(release == "EULEROSVIRT-2.5.0"){
	if(!isnull( res = isrpmvuln( pkg: "cpp", rpm: "cpp~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc", rpm: "gcc~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc-c++", rpm: "gcc-c++~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc-gfortran", rpm: "gcc-gfortran~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc", rpm: "libgcc~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran", rpm: "libgfortran~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp", rpm: "libgomp~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath", rpm: "libquadmath~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath-devel", rpm: "libquadmath-devel~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++", rpm: "libstdc++~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++-devel", rpm: "libstdc++-devel~4.8.3~10.h3", rls: "EULEROSVIRT-2.5.0" ) )){
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

