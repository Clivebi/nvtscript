if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1485" );
	script_cve_id( "CVE-2015-8393" );
	script_tag( name: "creation_date", value: "2020-04-16 05:58:02 +0000 (Thu, 16 Apr 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "Huawei EulerOS: Security Advisory for pcre (EulerOS-SA-2020-1485)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.2\\.2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1485" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1485" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'pcre' package(s) announced via the EulerOS-SA-2020-1485 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Integer overflow in the _IO_wstr_overflow function in libio/wstrops.c in the GNU C Library (aka glibc or libc6) before 2.22 allows context-dependent attackers to cause a denial of service (application crash) or possibly execute arbitrary code via vectors related to computing a size in bytes, which triggers a heap-based buffer overflow.(CVE-2015-8393)" );
	script_tag( name: "affected", value: "'pcre' package(s) on Huawei EulerOS Virtualization 3.0.2.2." );
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
if(release == "EULEROSVIRT-3.0.2.2"){
	if(!isnull( res = isrpmvuln( pkg: "pcre", rpm: "pcre~8.32~17.h10.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "pcre-devel", rpm: "pcre-devel~8.32~17.h10.eulerosv2r7", rls: "EULEROSVIRT-3.0.2.2" ) )){
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

