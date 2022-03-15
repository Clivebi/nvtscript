if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1183" );
	script_cve_id( "CVE-2018-1106" );
	script_tag( name: "creation_date", value: "2020-01-23 11:16:05 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for PackageKit (EulerOS-SA-2018-1183)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1183" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1183" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'PackageKit' package(s) announced via the EulerOS-SA-2018-1183 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An authentication bypass flaw has been found in PackageKit before 1.1.10 that allows users without administrator privileges to install signed packages. A local attacker can use this vulnerability to install vulnerable packages to further compromise a system.(CVE-2018-1106)" );
	script_tag( name: "affected", value: "'PackageKit' package(s) on Huawei EulerOS V2.0SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "PackageKit", rpm: "PackageKit~1.1.5~2", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "PackageKit-command-not-found", rpm: "PackageKit-command-not-found~1.1.5~2", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "PackageKit-glib", rpm: "PackageKit-glib~1.1.5~2", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "PackageKit-gstreamer-plugin", rpm: "PackageKit-gstreamer-plugin~1.1.5~2", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "PackageKit-gtk3-module", rpm: "PackageKit-gtk3-module~1.1.5~2", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "PackageKit-yum", rpm: "PackageKit-yum~1.1.5~2", rls: "EULEROS-2.0SP3" ) )){
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
