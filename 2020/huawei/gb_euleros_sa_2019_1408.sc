if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1408" );
	script_cve_id( "CVE-2017-12150", "CVE-2017-12151", "CVE-2017-12163", "CVE-2017-14746", "CVE-2017-15275", "CVE-2018-1050", "CVE-2018-10858" );
	script_tag( name: "creation_date", value: "2020-01-23 11:42:49 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2019-1408)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.1\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1408" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1408" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'samba' package(s) announced via the EulerOS-SA-2019-1408 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A null pointer dereference flaw was found in Samba RPC external printer service. An attacker could use this flaw to cause the printer spooler service to crash.(CVE-2018-1050)

A heap-buffer overflow was found in the way samba clients processed extra long filename in a directory listing. A malicious samba server could use this flaw to cause arbitrary code execution on a samba client. (CVE-2018-10858)

A use-after-free flaw was found in the way samba servers handled certain SMB1 requests. An unauthenticated attacker could send specially-crafted SMB1 requests to cause the server to crash or execute arbitrary code.(CVE-2017-14746)

A memory disclosure flaw was found in samba. An attacker could retrieve parts of server memory, which could contain potentially sensitive data, by sending specially-crafted requests to the samba server.(CVE-2017-15275)

It was found that samba did not enforce 'SMB signing' when certain configuration options were enabled. A remote attacker could launch a man-in-the-middle attack and retrieve information in plain-text.(CVE-2017-12150)

A flaw was found in the way samba client used encryption with the max protocol set as SMB3. The connection could lose the requirement for signing and encrypting to any DFS redirects, allowing an attacker to read or alter the contents of the connection via a man-in-the-middle attack.(CVE-2017-12151)

An information leak flaw was found in the way SMB1 protocol was implemented by Samba. A malicious client could use this flaw to dump server memory contents to a file on the samba share or to a shared printer, though the exact area of server memory cannot be controlled by the attacker.(CVE-2017-12163)" );
	script_tag( name: "affected", value: "'samba' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.1.0." );
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
if(release == "EULEROSVIRTARM64-3.0.1.0"){
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient", rpm: "libsmbclient~4.7.1~9.h2", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient", rpm: "libwbclient~4.7.1~9.h2", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-libs", rpm: "samba-client-libs~4.7.1~9.h2", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~4.7.1~9.h2", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common-libs", rpm: "samba-common-libs~4.7.1~9.h2", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-common-tools", rpm: "samba-common-tools~4.7.1~9.h2", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-libs", rpm: "samba-libs~4.7.1~9.h2", rls: "EULEROSVIRTARM64-3.0.1.0" ) )){
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

