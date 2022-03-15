if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1797" );
	script_cve_id( "CVE-2020-12049" );
	script_tag( name: "creation_date", value: "2020-07-31 05:40:04 +0000 (Fri, 31 Jul 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-04 21:17:00 +0000 (Thu, 04 Mar 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for dbus (EulerOS-SA-2020-1797)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP8" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1797" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1797" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'dbus' package(s) announced via the EulerOS-SA-2020-1797 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in dbus >= 1.3.0 before 1.12.18. The DBusServer in libdbus, as used in dbus-daemon, leaks file descriptors when a message exceeds the per-message file descriptor limit. A local attacker with access to the D-Bus system bus or another system service's private AF_UNIX socket could use this to make the system service reach its file descriptor limit, denying service to subsequent D-Bus clients.(CVE-2020-12049)" );
	script_tag( name: "affected", value: "'dbus' package(s) on Huawei EulerOS V2.0SP8." );
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
	if(!isnull( res = isrpmvuln( pkg: "dbus", rpm: "dbus~1.12.10~1.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-common", rpm: "dbus-common~1.12.10~1.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-daemon", rpm: "dbus-daemon~1.12.10~1.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-devel", rpm: "dbus-devel~1.12.10~1.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-libs", rpm: "dbus-libs~1.12.10~1.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-tools", rpm: "dbus-tools~1.12.10~1.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dbus-x11", rpm: "dbus-x11~1.12.10~1.h7.eulerosv2r8", rls: "EULEROS-2.0SP8" ) )){
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

