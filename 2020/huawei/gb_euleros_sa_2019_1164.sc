if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.1164" );
	script_cve_id( "CVE-2017-3735", "CVE-2018-0737" );
	script_tag( name: "creation_date", value: "2020-01-23 11:33:24 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for openssl (EulerOS-SA-2019-1164)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-1164" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1164" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'openssl' package(s) announced via the EulerOS-SA-2019-1164 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "While parsing an IPAddressFamily extension in an X.509 certificate, it is possible to do a one-byte overread. This would result in an incorrect text display of the certificate. This bug has been present since 2006 and is present in all versions of OpenSSL before 1.0.2m and 1.1.0g.(CVE-2017-3735)

OpenSSL RSA key generation was found to be vulnerable to cache side-channel attacks. An attacker with sufficient access to mount cache timing attacks during the RSA key generation process could recover parts of the private key.(CVE-2018-0737)" );
	script_tag( name: "affected", value: "'openssl' package(s) on Huawei EulerOS Virtualization 2.5.3." );
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
if(release == "EULEROSVIRT-2.5.3"){
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.2k~12.h5", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.2k~12.h5", rls: "EULEROSVIRT-2.5.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-libs", rpm: "openssl-libs~1.0.2k~12.h5", rls: "EULEROSVIRT-2.5.3" ) )){
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

