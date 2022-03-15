if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2019.2665" );
	script_cve_id( "CVE-2015-4645", "CVE-2015-4646" );
	script_tag( name: "creation_date", value: "2020-01-23 13:13:10 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-24 14:00:00 +0000 (Thu, 24 Oct 2019)" );
	script_name( "Huawei EulerOS: Security Advisory for squashfs-tools (EulerOS-SA-2019-2665)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP3" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2019-2665" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2665" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'squashfs-tools' package(s) announced via the EulerOS-SA-2019-2665 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "(1) unsquash-1.c, (2) unsquash-2.c, (3) unsquash-3.c, and (4) unsquash-4.c in Squashfs and sasquatch allow remote attackers to cause a denial of service (application crash) via a crafted input.(CVE-2015-4646)

Integer overflow in the read_fragment_table_4 function in unsquash-4.c in Squashfs and sasquatch allows remote attackers to cause a denial of service (application crash) via a crafted input, which triggers a stack-based buffer overflow.(CVE-2015-4645)" );
	script_tag( name: "affected", value: "'squashfs-tools' package(s) on Huawei EulerOS V2.0SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "squashfs-tools", rpm: "squashfs-tools~4.3~0.21.gitaae0aff4.h1", rls: "EULEROS-2.0SP3" ) )){
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

