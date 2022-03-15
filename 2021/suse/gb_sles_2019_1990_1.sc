if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1990.1" );
	script_cve_id( "CVE-2019-9704", "CVE-2019-9705" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-21 23:29:00 +0000 (Thu, 21 Mar 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1990-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1990-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191990-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cronie' package(s) announced via the SUSE-SU-2019:1990-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for cronie fixes the following issues:

Security issues fixed:
CVE-2019-9704: Fixed an insufficient check in the return value of calloc
 which could allow a local user to create Denial of Service by crashing
 the deamon (bsc#1128937).

CVE-2019-9705: Fixed an implementation vulnerability which could allow a
 local user to exhaust the memory resulting in Denial of Service
 (bsc#1128935).

Bug fixes:
Manual start of cron is possible even when it's already started using
 systemd (bsc#1133100).

Cron schedules only one job of crontab (bsc#1130746)." );
	script_tag( name: "affected", value: "'cronie' package(s) on SUSE CaaS Platform 3.0, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "cron", rpm: "cron~4.2~59.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cronie", rpm: "cronie~1.4.11~59.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cronie-debuginfo", rpm: "cronie-debuginfo~1.4.11~59.10.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cronie-debugsource", rpm: "cronie-debugsource~1.4.11~59.10.1", rls: "SLES12.0SP4" ) )){
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
