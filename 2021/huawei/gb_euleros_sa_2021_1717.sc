if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.1717" );
	script_cve_id( "CVE-2020-12401", "CVE-2020-12402" );
	script_tag( name: "creation_date", value: "2021-04-13 06:14:48 +0000 (Tue, 13 Apr 2021)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-26 16:05:00 +0000 (Mon, 26 Oct 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for nss (EulerOS-SA-2021-1717)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.9\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-1717" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1717" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'nss' package(s) announced via the EulerOS-SA-2021-1717 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "During RSA key generation, bignum implementations used a variation of the Binary Extended Euclidean Algorithm which entailed significantly input-dependent flow. This allowed an attacker able to perform electromagnetic-based side channel attacks to record traces leading to the recovery of the secret primes. *Note:* An unmodified Firefox browser does not generate RSA keys in normal operation and is not affected, but products built on top of it might.(CVE-2020-12402)

A flaw was found in nss. Using the EM side-channel, it is possible to extract the position of zero and non-zero wNAF digits while nss-certutil tool performs scalar multiplication during the ECDSA signature generation, leaking partial information about the ECDSA nonce. Given a small number of ECDSA signatures, this information can be used to steal the private key. The highest threat from this vulnerability is to data confidentiality.(CVE-2020-12401)" );
	script_tag( name: "affected", value: "'nss' package(s) on Huawei EulerOS Virtualization release 2.9.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "nss", rpm: "nss~3.40.1~11.h11.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-softokn", rpm: "nss-softokn~3.40.1~11.h11.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-util", rpm: "nss-util~3.40.1~11.h11.eulerosv2r9", rls: "EULEROSVIRT-2.9.1" ) )){
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

