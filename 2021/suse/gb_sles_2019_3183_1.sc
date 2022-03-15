if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.3183.1" );
	script_cve_id( "CVE-2019-3688", "CVE-2019-3690" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-20 16:15:00 +0000 (Fri, 20 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:3183-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:3183-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20193183-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'permissions' package(s) announced via the SUSE-SU-2019:3183-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for permissions fixes the following issues:

Security issues fixed:
CVE-2019-3688: Changed wrong ownership in /usr/sbin/pinger to root:squid
 which could have allowed a squid user to gain persistence by changing
 the binary (bsc#1093414).

CVE-2019-3690: Fixed a privilege escalation through untrusted symbolic
 links (bsc#1150734).

Other issue addressed:
Corrected a badly constracted file which could have allowed treating of
 the shell environment as permissions files (bsc#1097665,bsc#1047247).

Fixed a regression which caused sagmentation fault (bsc#1157198)." );
	script_tag( name: "affected", value: "'permissions' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "permissions", rpm: "permissions~20170707~3.14.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-debuginfo", rpm: "permissions-debuginfo~20170707~3.14.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-debugsource", rpm: "permissions-debugsource~20170707~3.14.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "permissions", rpm: "permissions~20170707~3.14.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-debuginfo", rpm: "permissions-debuginfo~20170707~3.14.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "permissions-debugsource", rpm: "permissions-debugsource~20170707~3.14.1", rls: "SLES12.0SP5" ) )){
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

