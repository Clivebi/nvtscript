if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1511.1" );
	script_cve_id( "CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2767", "CVE-2020-2773", "CVE-2020-2778", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2816", "CVE-2020-2830" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-05-26T12:07:57+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 12:07:57 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-02 15:15:00 +0000 (Tue, 02 Jun 2020)" );
	script_name( "SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2020:1511-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0LTSS)" );
	script_xref( name: "URL", value: "https://lists.suse.com/pipermail/sle-security-updates/2020-May/006870.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for 'java-11-openjdk'
  package(s) announced via the SUSE-SU-2020:1511-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "'java-11-openjdk' package(s) on SUSE Linux Enterprise Server 15" );
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
if(release == "SLES15.0LTSS"){
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk", rpm: "java-11-openjdk~11.0.7.0~3.42.4", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-debuginfo", rpm: "java-11-openjdk-debuginfo~11.0.7.0~3.42.4", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-debugsource", rpm: "java-11-openjdk-debugsource~11.0.7.0~3.42.4", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-demo", rpm: "java-11-openjdk-demo~11.0.7.0~3.42.4", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-devel", rpm: "java-11-openjdk-devel~11.0.7.0~3.42.4", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk-headless", rpm: "java-11-openjdk-headless~11.0.7.0~3.42.4", rls: "SLES15.0LTSS" ) )){
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

