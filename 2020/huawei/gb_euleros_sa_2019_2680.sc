if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2680" );
	script_cve_id( "CVE-2016-10169", "CVE-2018-19840" );
	script_tag( name: "creation_date", value: "2020-01-23 13:13:36 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for wavpack (EulerOS-SA-2019-2680)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2680" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2680" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'wavpack' package(s) announced via the EulerOS-SA-2019-2680 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The function WavpackPackInit in pack_utils.c in libwavpack.a in WavPack through 5.1.0 allows attackers to cause a denial-of-service (resource exhaustion caused by an infinite loop) via a crafted wav audio file because WavpackSetConfiguration64 mishandles a sample rate of zero.(CVE-2018-19840)

The read_code function in read_words.c in Wavpack before 5.1.0 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted WV file.(CVE-2016-10169)" );
	script_tag( name: "affected", value: "'wavpack' package(s) on Huawei EulerOS V2.0SP3." );
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
if(release == "EULEROS-2.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "wavpack", rpm: "wavpack~4.60.1~9.h2", rls: "EULEROS-2.0SP3" ) )){
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

