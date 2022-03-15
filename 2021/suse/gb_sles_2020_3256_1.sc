if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3256.1" );
	script_cve_id( "CVE-2019-11059", "CVE-2019-11690", "CVE-2019-13103", "CVE-2019-13104", "CVE-2019-13106", "CVE-2019-14192", "CVE-2019-14193", "CVE-2019-14194", "CVE-2019-14195", "CVE-2019-14196", "CVE-2019-14197", "CVE-2019-14198", "CVE-2019-14199", "CVE-2019-14200", "CVE-2019-14201", "CVE-2019-14202", "CVE-2019-14203", "CVE-2019-14204", "CVE-2020-10648", "CVE-2020-8432" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-13 12:20:00 +0000 (Mon, 13 May 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3256-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3256-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203256-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'u-boot' package(s) announced via the SUSE-SU-2020:3256-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for u-boot fixes the following issues:

Fix CVE-2019-13106 (bsc#1144656), CVE-2019-13104 (bsc#1144675),
CVE-2019-14192 (bsc#1143777), CVE-2019-14193 (bsc#1143817), CVE-2019-14199
(bsc#1143824), CVE-2019-14197 (bsc#1143821), CVE-2019-14200 (bsc#1143825),
CVE-2019-14201 (bsc#1143827), CVE-2019-14202 (bsc#1143828), CVE-2019-14203
(bsc#1143830), CVE-2019-14204 (bsc#1143831), CVE-2019-14194 (bsc#1143818),
CVE-2019-14198 (bsc#1143823), CVE-2019-14195 (bsc#1143819), CVE-2019-14196
(bsc#1143820), CVE-2019-13103 (bsc#1143463), CVE-2020-8432 (bsc#1162198),
CVE-2019-11059 (bsc#1134853), CVE-2019-11690 (bsc#1134157) and CVE-2020-10648 (bsc#1167209)" );
	script_tag( name: "affected", value: "'u-boot' package(s) on SUSE Linux Enterprise Server 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "u-boot-rpi3", rpm: "u-boot-rpi3~2018.03~4.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "u-boot-tools", rpm: "u-boot-tools~2018.03~4.3.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "u-boot-tools-debuginfo", rpm: "u-boot-tools-debuginfo~2018.03~4.3.1", rls: "SLES12.0SP4" ) )){
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

