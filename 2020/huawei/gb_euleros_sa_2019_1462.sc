if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1462" );
	script_cve_id( "CVE-2017-2616" );
	script_tag( name: "creation_date", value: "2020-01-23 11:48:09 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for util-linux (EulerOS-SA-2019-1462)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1462" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1462" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'util-linux' package(s) announced via the EulerOS-SA-2019-1462 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A race condition was found in the way su handled the management of child processes. A local authenticated attacker could use this flaw to kill other processes with root privileges under specific conditions.(CVE-2017-2616)" );
	script_tag( name: "affected", value: "'util-linux' package(s) on Huawei EulerOS Virtualization 3.0.1.0." );
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
if(release == "EULEROSVIRT-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "libblkid", rpm: "libblkid~2.23.2~52.1.h3.eulerosv2r7", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmount", rpm: "libmount~2.23.2~52.1.h3.eulerosv2r7", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libuuid", rpm: "libuuid~2.23.2~52.1.h3.eulerosv2r7", rls: "EULEROSVIRT-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "util-linux", rpm: "util-linux~2.23.2~52.1.h3.eulerosv2r7", rls: "EULEROSVIRT-3.0.1.0" ) )){
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

