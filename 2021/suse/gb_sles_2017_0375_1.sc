if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0375.1" );
	script_cve_id( "CVE-2014-3215" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:01 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-03 17:08:00 +0000 (Thu, 03 Jan 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0375-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0375-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170375-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libcap-ng' package(s) announced via the SUSE-SU-2017:0375-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "libcap-ng was updated to fix one security issue.
This security issue was fixed:
- CVE-2014-3215: seunshare in policycoreutils (which uses libcap-ng) is
 owned by root with 4755 permissions, and executes programs in a way that
 changes the relationship between the setuid system call and the
 getresuid saved set-user-ID value, which made it easier for local users
 to gain privileges by leveraging a program that mistakenly expected that
 it could permanently drop privileges (bsc#876832)." );
	script_tag( name: "affected", value: "'libcap-ng' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libcap-ng-utils", rpm: "libcap-ng-utils~0.6.3~1.9.6", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcap-ng0", rpm: "libcap-ng0~0.6.3~1.9.6", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcap-ng0-32bit", rpm: "libcap-ng0-32bit~0.6.3~1.9.6", rls: "SLES11.0SP4" ) )){
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

