if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1968" );
	script_cve_id( "CVE-2020-27840", "CVE-2021-20277" );
	script_tag( name: "creation_date", value: "2021-06-07 09:15:23 +0000 (Mon, 07 Jun 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 19:46:00 +0000 (Wed, 26 May 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2021-1968)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1968" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1968" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'samba' package(s) announced via the EulerOS-SA-2021-1968 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in Samba's libldb. Multiple, consecutive leading spaces in an LDAP attribute can lead to an out-of-bounds memory write, leading to a crash of the LDAP server process handling the request. The highest threat from this vulnerability is to system availability.(CVE-2021-20277)

An extensible library that implements an LDAP like API to access remote LDAPservers, or use local tdb databases.(CVE-2020-27840)" );
	script_tag( name: "affected", value: "'samba' package(s) on Huawei EulerOS Virtualization release 2.9.0." );
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
if(release == "EULEROSVIRT-2.9.0"){
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~4.11.6~6.h14.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient", rpm: "libwbclient~4.11.6~6.h14.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.11.6~6.h14.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~4.11.6~6.h14.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common-tools", rpm: "samba-common-tools~4.11.6~6.h14.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.11.6~6.h14.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
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

