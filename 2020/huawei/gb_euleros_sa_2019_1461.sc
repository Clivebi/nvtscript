if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1461" );
	script_cve_id( "CVE-2015-5276" );
	script_tag( name: "creation_date", value: "2020-01-23 11:48:08 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-12 19:05:00 +0000 (Tue, 12 Feb 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for gcc (EulerOS-SA-2019-1461)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1461" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1461" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'gcc' package(s) announced via the EulerOS-SA-2019-1461 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The std::random_device class in libstdc++ in the GNU Compiler Collection (aka GCC) before 4.9.4 does not properly handle short reads from blocking sources, which makes it easier for context-dependent attackers to predict the random values via unspecified vectors.(CVE-2015-5276)" );
	script_tag( name: "affected", value: "'gcc' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
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
if(release == "EULEROSVIRT-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "cpp", rpm: "cpp~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc", rpm: "gcc~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc-c++", rpm: "gcc-c++~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gcc-gfortran", rpm: "gcc-gfortran~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgcc", rpm: "libgcc~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgfortran", rpm: "libgfortran~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgomp", rpm: "libgomp~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath", rpm: "libquadmath~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libquadmath-devel", rpm: "libquadmath-devel~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++", rpm: "libstdc++~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libstdc++-devel", rpm: "libstdc++-devel~4.8.5~28", rls: "EULEROSVIRT-3.0.1.0" ) )){
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

