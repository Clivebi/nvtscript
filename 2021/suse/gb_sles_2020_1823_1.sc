if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1823.1" );
	script_cve_id( "CVE-2018-8956", "CVE-2020-11868", "CVE-2020-13817", "CVE-2020-15025" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-05-26T12:07:57+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 12:07:57 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 02:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_name( "SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2020:1823-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0LTSS)" );
	script_xref( name: "URL", value: "https://lists.suse.com/pipermail/sle-security-updates/2020-July/007066.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for 'ntp'
  package(s) announced via the SUSE-SU-2020:1823-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "'ntp' package(s) on SUSE Linux Enterprise Server 15" );
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
	if(!isnull( res = isrpmvuln( pkg: "ntp", rpm: "ntp~4.2.8p15~4.10.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-debuginfo", rpm: "ntp-debuginfo~4.2.8p15~4.10.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ntp-debugsource", rpm: "ntp-debugsource~4.2.8p15~4.10.1", rls: "SLES15.0LTSS" ) )){
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

