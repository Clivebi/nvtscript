if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1342" );
	script_cve_id( "CVE-2018-1050", "CVE-2018-10858" );
	script_tag( name: "creation_date", value: "2020-01-23 11:39:56 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-26 08:15:00 +0000 (Wed, 26 Jun 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2019-1342)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1342" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1342" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'samba' package(s) announced via the EulerOS-SA-2019-1342 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "All versions of Samba from 4.0.0 onwards are vulnerable to a denial of service attack when the RPC spoolss service is configured to be run as an external daemon. Missing input sanitization checks on some of the input parameters to spoolss RPC calls could cause the print spooler service to crash.(CVE-2018-1050)

A heap-buffer overflow was found in the way samba clients processed extra long filename in a directory listing. A malicious samba server could use this flaw to cause arbitrary code execution on a samba client. Samba versions before 4.6.16, 4.7.9 and 4.8.4 are vulnerable.(CVE-2018-10858)" );
	script_tag( name: "affected", value: "'samba' package(s) on Huawei EulerOS V2.0SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient", rpm: "libwbclient~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-libs", rpm: "samba-client-libs~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common-libs", rpm: "samba-common-libs~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common-tools", rpm: "samba-common-tools~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-python", rpm: "samba-python~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-clients", rpm: "samba-winbind-clients~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-modules", rpm: "samba-winbind-modules~4.6.2~8.h6", rls: "EULEROS-2.0SP3" ) )){
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

