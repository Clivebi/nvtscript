if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2193" );
	script_cve_id( "CVE-2018-17336" );
	script_tag( name: "creation_date", value: "2020-01-23 12:37:50 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for udisks2 (EulerOS-SA-2019-2193)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2193" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2193" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'udisks2' package(s) announced via the EulerOS-SA-2019-2193 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "UDisks 2.8.0 has a format string vulnerability in udisks_log in udiskslogging.c, allowing attackers to obtain sensitive information (stack contents), cause a denial of service (memory corruption), or possibly have unspecified other impact via a malformed filesystem label, as demonstrated by %d or %n substrings.(CVE-2018-17336)" );
	script_tag( name: "affected", value: "'udisks2' package(s) on Huawei EulerOS V2.0SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "libudisks2", rpm: "libudisks2~2.7.3~6.h1.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "udisks2", rpm: "udisks2~2.7.3~6.h1.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

