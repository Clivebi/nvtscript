if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2207" );
	script_cve_id( "CVE-2017-5209", "CVE-2017-5545", "CVE-2017-6435" );
	script_tag( name: "creation_date", value: "2020-01-23 12:38:58 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-02 10:15:00 +0000 (Thu, 02 Apr 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for libplist (EulerOS-SA-2019-2207)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP5" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2207" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2207" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libplist' package(s) announced via the EulerOS-SA-2019-2207 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The parse_string_node function in bplist.c in libimobiledevice libplist 1.12 allows local users to cause a denial of service (memory corruption) via a crafted plist file.(CVE-2017-6435)

The base64decode function in base64.c in libimobiledevice libplist through 1.12 allows attackers to obtain sensitive information from process memory or cause a denial of service (buffer over-read) via split encoded Apple Property List data.(CVE-2017-5209)

The main function in plistutil.c in libimobiledevice libplist through 1.12 allows attackers to obtain sensitive information from process memory or cause a denial of service (buffer over-read) via Apple Property List data that is too short.(CVE-2017-5545)" );
	script_tag( name: "affected", value: "'libplist' package(s) on Huawei EulerOS V2.0SP5." );
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
if(release == "EULEROS-2.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libplist", rpm: "libplist~1.12~3.h2.eulerosv2r7", rls: "EULEROS-2.0SP5" ) )){
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

