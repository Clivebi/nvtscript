if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2191" );
	script_cve_id( "CVE-2021-20208" );
	script_tag( name: "creation_date", value: "2021-07-13 12:58:52 +0000 (Tue, 13 Jul 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-29 14:56:00 +0000 (Thu, 29 Apr 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for cifs-utils (EulerOS-SA-2021-2191)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2191" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2191" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'cifs-utils' package(s) announced via the EulerOS-SA-2021-2191 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was found in cifs-utils in versions before 6.13. A user when mounting a krb5 CIFS file system from within a container can use Kerberos credentials of the host. The highest threat from this vulnerability is to data confidentiality and integrity.(CVE-2021-20208)" );
	script_tag( name: "affected", value: "'cifs-utils' package(s) on Huawei EulerOS Virtualization release 2.9.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "cifs-utils", rpm: "cifs-utils~6.10~0.h2.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
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
