if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2021.2436" );
	script_cve_id( "CVE-2019-25031", "CVE-2019-25032", "CVE-2019-25033", "CVE-2019-25034", "CVE-2019-25035", "CVE-2019-25036", "CVE-2019-25037", "CVE-2019-25038", "CVE-2019-25039", "CVE-2019-25040", "CVE-2019-25041", "CVE-2019-25042", "CVE-2020-28935" );
	script_tag( name: "creation_date", value: "2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)" );
	script_version( "2021-09-15T02:24:22+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 02:24:22 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 22:15:00 +0000 (Fri, 11 Jun 2021)" );
	script_name( "Huawei EulerOS: Security Advisory for unbound (EulerOS-SA-2021-2436)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2021-2436" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2436" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'unbound' package(s) announced via the EulerOS-SA-2021-2436 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "NLnet Labs Unbound, up to and including version 1.12.0, and NLnet Labs NSD, up to and including version 4.3.3, contain a local vulnerability that would allow for a local symlink attack. When writing the PID file, Unbound and NSD create the file if it is not there, or open an existing file for writing. In case the file was already present, they would follow symlinks if the file happened to be a symlink instead of a regular file. An additional chown of the file would then take place after it was written, making the user Unbound/NSD is supposed to run as the new owner of the file. If an attacker has local access to the user Unbound/NSD runs as, she could create a symlink in place of the PID file pointing to a file that she would like to erase. If then Unbound/NSD is killed and the PID file is not cleared, upon restarting with root privileges, Unbound/NSD will rewrite any file pointed at by the symlink. This is a local vulnerability that could create a Denial of Service of the system Unbound/NSD is running on. It requires an attacker having access to the limited permission user Unbound/NSD runs as and point through the symlink to a critical file on the system.(CVE-2020-28935)

Unbound before 1.9.5 allows an assertion failure via a compressed name in dname_pkt_copy.(CVE-2019-25041)

Unbound before 1.9.5 allows an integer overflow in the regional allocator via the ALIGN_UP macro.(CVE-2019-25033)

Unbound before 1.9.5 allows an integer overflow in sldns_str2wire_dname_buf_origin, leading to an out-of-bounds write.(CVE-2019-25034)

Unbound before 1.9.5 allows an out-of-bounds write in sldns_bget_token_par.(CVE-2019-25035)

Unbound before 1.9.5 allows an infinite loop via a compressed name in dname_pkt_copy.(CVE-2019-25040)

Unbound before 1.9.5 allows an integer overflow in a size calculation in respip/respip.c.(CVE-2019-25039)

Unbound before 1.9.5 allows an assertion failure and denial of service in synth_cname.(CVE-2019-25036)

Unbound before 1.9.5 allows an integer overflow in a size calculation in dnscrypt/dnscrypt.c.(CVE-2019-25038)

Unbound before 1.9.5 allows an out-of-bounds write via a compressed name in rdata_copy.(CVE-2019-25042)

Unbound before 1.9.5 allows an assertion failure and denial of service in dname_pkt_copy via an invalid packet.(CVE-2019-25037)

Unbound before 1.9.5 allows configuration injection in create_unbound_ad_servers.sh upon a successful man-in-the-middle attack against a cleartext HTTP session.(CVE-2019-25031)

Unbound before 1.9.5 allows an integer overflow in the regional allocator via regional_alloc.(CVE-2019-25032)" );
	script_tag( name: "affected", value: "'unbound' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "unbound", rpm: "unbound~1.6.6~1.h5", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "unbound-libs", rpm: "unbound-libs~1.6.6~1.h5", rls: "EULEROS-2.0SP2" ) )){
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
