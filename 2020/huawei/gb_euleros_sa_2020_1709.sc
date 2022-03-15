if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2020.1709" );
	script_cve_id( "CVE-2020-11100" );
	script_tag( name: "creation_date", value: "2020-06-26 07:27:50 +0000 (Fri, 26 Jun 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-24 16:15:00 +0000 (Thu, 24 Dec 2020)" );
	script_name( "Huawei EulerOS: Security Advisory for haproxy (EulerOS-SA-2020-1709)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRTARM64\\-3\\.0\\.6\\.0" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2020-1709" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1709" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'haproxy' package(s) announced via the EulerOS-SA-2020-1709 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In hpack_dht_insert in hpack-tbl.c in the HPACK decoder in HAProxy 1.8 through 2.x before 2.1.4, a remote attacker can write arbitrary bytes around a certain location on the heap via a crafted HTTP/2 request, possibly causing remote code execution.(CVE-2020-11100)" );
	script_tag( name: "affected", value: "'haproxy' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "haproxy", rpm: "haproxy~1.8.14~1.h2.eulerosv2r8", rls: "EULEROSVIRTARM64-3.0.6.0" ) )){
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

