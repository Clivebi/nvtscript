if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2266" );
	script_cve_id( "CVE-2020-35512" );
	script_tag( name: "creation_date", value: "2021-08-09 10:11:09 +0000 (Mon, 09 Aug 2021)" );
	script_version( "2021-08-09T11:38:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 11:38:50 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-08 21:15:00 +0000 (Mon, 08 Mar 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for dbus (EulerOS-SA-2021-2266)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2266" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2266" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'dbus' package(s) announced via the EulerOS-SA-2021-2266 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A use-after-free flaw was found in D-Bus Development branch <= 1.13.16, dbus-1.12.x stable branch <= 1.12.18, and dbus-1.10.x and older branches <= 1.10.30 when a system has multiple usernames sharing the same UID. When a set of policy rules references these usernames, D-Bus may free some memory in the heap, which is still used by data structures necessary for the other usernames sharing the UID, possibly leading to a crash or other undefined behaviors(CVE-2020-35512)" );
	script_tag( name: "affected", value: "'dbus' package(s) on Huawei EulerOS V2.0SP9." );
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
if(release == "EULEROS-2.0SP9"){
	if(!isnull( res = isrpmvuln( pkg: "dbus", rpm: "dbus~1.12.16~13.h5.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-common", rpm: "dbus-common~1.12.16~13.h5.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-daemon", rpm: "dbus-daemon~1.12.16~13.h5.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-libs", rpm: "dbus-libs~1.12.16~13.h5.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-tools", rpm: "dbus-tools~1.12.16~13.h5.eulerosv2r9", rls: "EULEROS-2.0SP9" ) )){
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

