if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2332" );
	script_cve_id( "CVE-2021-3504" );
	script_tag( name: "creation_date", value: "2021-09-04 02:25:52 +0000 (Sat, 04 Sep 2021)" );
	script_version( "2021-09-04T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-09-04 02:25:52 +0000 (Sat, 04 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 18:35:00 +0000 (Mon, 21 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for hivex (EulerOS-SA-2021-2332)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2332" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2332" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'hivex' package(s) announced via the EulerOS-SA-2021-2332 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in the hivex library in versions before 1.3.20. It is caused due to a lack of bounds check within the hivex_open function. An attacker could input a specially crafted Windows Registry (hive) file which would cause hivex to read memory beyond its normal bounds or cause the program to crash. The highest threat from this vulnerability is to system availability.(CVE-2021-3504)" );
	script_tag( name: "affected", value: "'hivex' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "hivex", rpm: "hivex~1.3.10~6.9.h2.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-hivex", rpm: "perl-hivex~1.3.10~6.9.h2.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

