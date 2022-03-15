if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.2504" );
	script_cve_id( "CVE-2020-14318", "CVE-2020-14323" );
	script_tag( name: "creation_date", value: "2020-12-01 06:58:41 +0000 (Tue, 01 Dec 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-24 16:15:00 +0000 (Thu, 24 Dec 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2020-2504)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP9\\-X86_64" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-2504" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2504" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'samba' package(s) announced via the EulerOS-SA-2020-2504 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "As Samba internally opens an underlying file system handle on a directory when a client requests an open, even for FILE_READ_ATTRIBUTES then if the underlying file system permissions don&#39,t allow &quot,r&quot, (read) access for the connected user, then the handle open request will be denied.&quot(CVE-2020-14318)

A null pointer dereference flaw was found in samba's Winbind service in versions before 4.11.15, before 4.12.9 and before 4.13.1. A local user could use this flaw to crash the winbind service causing denial of service.(CVE-2020-14323)" );
	script_tag( name: "affected", value: "'samba' package(s) on Huawei EulerOS V2.0SP9(x86_64)." );
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
if(release == "EULEROS-2.0SP9-x86_64"){
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient", rpm: "libwbclient~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common-tools", rpm: "samba-common-tools~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-clients", rpm: "samba-winbind-clients~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-modules", rpm: "samba-winbind-modules~4.11.6~6.h9.eulerosv2r9", rls: "EULEROS-2.0SP9-x86_64" ) )){
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

