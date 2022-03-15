if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.3237.1" );
	script_cve_id( "CVE-2021-41054" );
	script_tag( name: "creation_date", value: "2021-09-28 06:58:32 +0000 (Tue, 28 Sep 2021)" );
	script_version( "2021-09-28T06:58:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 06:58:32 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-24 12:52:00 +0000 (Fri, 24 Sep 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:3237-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:3237-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20213237-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'atftp' package(s) announced via the SUSE-SU-2021:3237-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for atftp fixes the following issues:

CVE-2021-41054: Fixed buffer overflow caused by combination of data,
 OACK, and other options (bsc#1190522)." );
	script_tag( name: "affected", value: "'atftp' package(s) on SUSE Linux Enterprise Server 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "atftp", rpm: "atftp~0.7.0~160.11.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "atftp-debuginfo", rpm: "atftp-debuginfo~0.7.0~160.11.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "atftp-debugsource", rpm: "atftp-debugsource~0.7.0~160.11.1", rls: "SLES12.0SP5" ) )){
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

