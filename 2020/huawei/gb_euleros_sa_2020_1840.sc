if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1840" );
	script_cve_id( "CVE-2018-10896" );
	script_tag( name: "creation_date", value: "2020-08-31 07:03:13 +0000 (Mon, 31 Aug 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-29 20:19:00 +0000 (Thu, 29 Oct 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for cloud-init (EulerOS-SA-2020-1840)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1840" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1840" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'cloud-init' package(s) announced via the EulerOS-SA-2020-1840 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The default cloud-init configuration, in cloud-init 0.6.2 and newer, included 'ssh_deletekeys: 0', disabling cloud-init's deletion of ssh host keys. In some environments, this could lead to instances created by cloning a golden master or template system, sharing ssh host keys, and being able to impersonate one another or conduct man-in-the-middle attacks.(CVE-2018-10896)" );
	script_tag( name: "affected", value: "'cloud-init' package(s) on Huawei EulerOS V2.0SP8." );
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
if(release == "EULEROS-2.0SP8"){
	if(!isnull( res = isrpmvuln( pkg: "cloud-init", rpm: "cloud-init~17.1~7.h14.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

