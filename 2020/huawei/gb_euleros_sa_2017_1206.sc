if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2017.1206" );
	script_cve_id( "CVE-2016-10198", "CVE-2016-10199", "CVE-2016-9446", "CVE-2016-9810", "CVE-2016-9811", "CVE-2017-5837", "CVE-2017-5838", "CVE-2017-5839", "CVE-2017-5840", "CVE-2017-5841", "CVE-2017-5842", "CVE-2017-5843", "CVE-2017-5844", "CVE-2017-5845", "CVE-2017-5848" );
	script_tag( name: "creation_date", value: "2020-01-23 10:58:40 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "Huawei EulerOS: Security Advisory for gstreamer (EulerOS-SA-2017-1206)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROS\\-2\\.0SP2" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2017-1206" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1206" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'gstreamer' package(s) announced via the EulerOS-SA-2017-1206 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws were found in gstreamer1, gstreamer1-plugins-base, gstreamer1-plugins-good, and gstreamer1-plugins-bad-free packages. An attacker could potentially use these flaws to crash applications which use the GStreamer framework. (CVE-2016-9446, CVE-2016-9810, CVE-2016-9811, CVE-2016-10198, CVE-2016-10199, CVE-2017-5837, CVE-2017-5838, CVE-2017-5839, CVE-2017-5840, CVE-2017-5841, CVE-2017-5842, CVE-2017-5843, CVE-2017-5844, CVE-2017-5845, CVE-2017-5848)" );
	script_tag( name: "affected", value: "'gstreamer' package(s) on Huawei EulerOS V2.0SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "gstreamer1", rpm: "gstreamer1~1.10.4~2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer1-devel", rpm: "gstreamer1-devel~1.10.4~2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer1-plugins-base", rpm: "gstreamer1-plugins-base~1.10.4~1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer1-plugins-base-devel", rpm: "gstreamer1-plugins-base-devel~1.10.4~1", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer1-plugins-good", rpm: "gstreamer1-plugins-good~1.10.4~2", rls: "EULEROS-2.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer1-plugins-bad-free", rpm: "gstreamer1-plugins-bad-free~1.10.4~2", rls: "EULEROS-2.0SP2" ) )){
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

