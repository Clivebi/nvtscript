if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1787" );
	script_cve_id( "CVE-2018-14424", "CVE-2019-3825" );
	script_tag( name: "creation_date", value: "2021-05-03 06:20:08 +0000 (Mon, 03 May 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-18 20:21:00 +0000 (Thu, 18 Oct 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for gdm (EulerOS-SA-2021-1787)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1787" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1787" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'gdm' package(s) announced via the EulerOS-SA-2021-1787 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in gdm before 3.31.4. When timed login is enabled in configuration, an attacker could bypass the lock screen by selecting the timed login user and waiting for the timer to expire, at which time they would gain access to the logged-in user's session.(CVE-2019-3825)

The daemon in GDM through 3.29.1 does not properly unexport display objects from its D-Bus interface when they are destroyed, which allows a local attacker to trigger a use-after-free via a specially crafted sequence of D-Bus method calls, resulting in a denial of service or potential code execution.(CVE-2018-14424)" );
	script_tag( name: "affected", value: "'gdm' package(s) on Huawei EulerOS V2.0SP3." );
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
if(release == "EULEROS-2.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "gdm", rpm: "gdm~3.14.2~12.h6", rls: "EULEROS-2.0SP3" ) )){
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

