if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1730" );
	script_cve_id( "CVE-2020-14019" );
	script_tag( name: "creation_date", value: "2021-04-13 06:15:19 +0000 (Tue, 13 Apr 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-07 12:15:00 +0000 (Fri, 07 Aug 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for python-rtslib (EulerOS-SA-2021-1730)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1730" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1730" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'python-rtslib' package(s) announced via the EulerOS-SA-2021-1730 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in Open-iSCSI rtslib-fb through versions 2.1.72, where it has weak permissions for /etc/target/saveconfig.json because the shutil.copyfile, instead of shutil.copy is used, and permissions are not preserved upon editing. This flaw allows an attacker with prior access to /etc/target/saveconfig.json to access a later version, resulting in a loss of integrity, depending on their permission settings. The highest threat from this vulnerability is to confidentiality.(CVE-2020-14019)" );
	script_tag( name: "affected", value: "'python-rtslib' package(s) on Huawei EulerOS Virtualization release 2.9.1." );
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
if(release == "EULEROSVIRT-2.9.1"){
	if(!isnull( res = isrpmvuln( pkg: "python3-rtslib", rpm: "python3-rtslib~2.1.70~3.h1.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "target-restore", rpm: "target-restore~2.1.70~3.h1.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
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
