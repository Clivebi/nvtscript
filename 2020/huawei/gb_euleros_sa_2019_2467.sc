if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2467" );
	script_cve_id( "CVE-2018-12404" );
	script_tag( name: "creation_date", value: "2020-01-23 13:00:23 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-12 07:15:00 +0000 (Fri, 12 Feb 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for nss (EulerOS-SA-2019-2467)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2467" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2467" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'nss' package(s) announced via the EulerOS-SA-2019-2467 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A cached side channel attack during handshakes using RSA encryption could allow for the decryption of encrypted content. This is a variant of the Adaptive Chosen Ciphertext attack (AKA Bleichenbacher attack) and affects all NSS versions prior to NSS 3.41.(CVE-2018-12404)" );
	script_tag( name: "affected", value: "'nss' package(s) on Huawei EulerOS V2.0SP2." );
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
if(release == "EULEROS-2.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "nss", rpm: "nss~3.36.0~7.h2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.36.0~7.h2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-sysinit", rpm: "nss-sysinit~3.36.0~7.h2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.36.0~7.h2", rls: "EULEROS-2.0SP2" ) )){
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

