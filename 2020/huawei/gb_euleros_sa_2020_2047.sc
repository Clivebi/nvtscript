if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.2047" );
	script_cve_id( "CVE-2017-2885", "CVE-2018-12910" );
	script_tag( name: "creation_date", value: "2020-09-29 13:42:00 +0000 (Tue, 29 Sep 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-07 17:15:00 +0000 (Mon, 07 Dec 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for libsoup (EulerOS-SA-2020-2047)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.6\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-2047" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2047" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'libsoup' package(s) announced via the EulerOS-SA-2020-2047 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A stack-based buffer overflow flaw was discovered within the HTTP processing of libsoup. A remote attacker could exploit this flaw to cause a crash or, potentially, execute arbitrary code by sending a specially crafted HTTP request to a server using the libsoup HTTP server functionality or by tricking a user into connecting to a malicious HTTP server with an application using the libsoup HTTP client functionality.(CVE-2017-2885)

The get_cookies function in soup-cookie-jar.c in libsoup 2.63.2 allows attackers to have unspecified impact via an empty hostname.(CVE-2018-12910)" );
	script_tag( name: "affected", value: "'libsoup' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0." );
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
if(release == "EULEROSVIRTARM64-3.0.6.0"){
	if(!isnull( res = isrpmvuln( pkg: "libsoup", rpm: "libsoup~2.64.1~1.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.6.0" ) )){
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

