if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1640" );
	script_cve_id( "CVE-2019-17006", "CVE-2019-17007", "CVE-2020-12399", "CVE-2020-12400", "CVE-2020-12403", "CVE-2020-25648" );
	script_tag( name: "creation_date", value: "2021-03-12 07:24:56 +0000 (Fri, 12 Mar 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 16:59:00 +0000 (Fri, 19 Feb 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for nss (EulerOS-SA-2021-1640)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1640" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1640" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'nss' package(s) announced via the EulerOS-SA-2021-1640 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In Network Security Services (NSS) before 3.46, several cryptographic primitives had missing length checks. In cases where the application calling the library did not perform a sanity check on the inputs it could result in a crash due to a buffer overflow.(CVE-2019-17006)

NSS has shown timing differences when performing DSA signatures, which was exploitable and could eventually leak private keys. This vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and Firefox ESR < 68.9.(CVE-2020-12399)

When converting coordinates from projective to affine, the modular inversion was not performed in constant time, resulting in a possible timing-based side channel attack. This vulnerability affects Firefox < 80 and Firefox for Android < 80.(CVE-2020-12400)

A flaw was found in the way CHACHA20-POLY1305 was implemented in NSS. When using multi-part Chacha20, it could cause out-of-bounds reads. This issue was fixed by explicitly disabling multi-part ChaCha20 (which was not functioning correctly) and strictly enforcing tag length. The highest threat from(CVE-2020-12403)

A flaw was found in the way NSS handled CCS (ChangeCipherSpec) messages in TLS 1.3. This flaw allows a remote attacker to send multiple CCS messages, causing a denial of service for servers compiled with the NSS library. The highest threat from this vulnerability is to system availability. This flaw affects NSS versions before 3.58.(CVE-2020-25648)

In Network Security Services before 3.44, a malformed Netscape Certificate Sequence can cause NSS to crash, resulting in a denial of service.(CVE-2019-17007)" );
	script_tag( name: "affected", value: "'nss' package(s) on Huawei EulerOS Virtualization release 2.9.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "nss", rpm: "nss~3.40.1~11.h8.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-softokn", rpm: "nss-softokn~3.40.1~11.h8.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-util", rpm: "nss-util~3.40.1~11.h8.eulerosv2r9", rls: "EULEROSVIRT-2.9.0" ) )){
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

