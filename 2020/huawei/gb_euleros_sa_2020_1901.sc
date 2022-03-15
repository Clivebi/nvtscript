if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1901" );
	script_cve_id( "CVE-2017-6363", "CVE-2018-14553" );
	script_tag( name: "creation_date", value: "2020-08-31 07:04:58 +0000 (Mon, 31 Aug 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-27 19:09:00 +0000 (Thu, 27 Feb 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for gd (EulerOS-SA-2020-1901)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.6\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1901" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1901" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'gd' package(s) announced via the EulerOS-SA-2020-1901 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2018-14553)

** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.(CVE-2017-6363)" );
	script_tag( name: "affected", value: "'gd' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0." );
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
if(release == "EULEROSVIRTARM64-3.0.6.0"){
	if(!isnull( res = isrpmvuln( pkg: "gd", rpm: "gd~2.2.5~3.h4.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.6.0" ) )){
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

