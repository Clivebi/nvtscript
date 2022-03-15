if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2778.1" );
	script_cve_id( "CVE-2018-14036" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-06 16:16:00 +0000 (Thu, 06 Sep 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2778-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2778-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192778-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'accountsservice' package(s) announced via the SUSE-SU-2019:2778-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for accountsservice fixes the following issues:

Security issue fixed:
CVE-2018-14036: Prevent directory traversal caused by an insufficient
 path check in user_change_icon_file_authorized_cb() (bsc#1099699).

Non-security issue fixed:
Improved wtmp io performance (bsc#1139487)." );
	script_tag( name: "affected", value: "'accountsservice' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Desktop 12-SP5, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "accountsservice", rpm: "accountsservice~0.6.42~16.8.3", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-debuginfo", rpm: "accountsservice-debuginfo~0.6.42~16.8.3", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-debugsource", rpm: "accountsservice-debugsource~0.6.42~16.8.3", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-lang", rpm: "accountsservice-lang~0.6.42~16.8.3", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaccountsservice0", rpm: "libaccountsservice0~0.6.42~16.8.3", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaccountsservice0-debuginfo", rpm: "libaccountsservice0-debuginfo~0.6.42~16.8.3", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-AccountsService-1_0", rpm: "typelib-1_0-AccountsService-1_0~0.6.42~16.8.3", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "accountsservice", rpm: "accountsservice~0.6.42~16.8.3", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-debuginfo", rpm: "accountsservice-debuginfo~0.6.42~16.8.3", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-debugsource", rpm: "accountsservice-debugsource~0.6.42~16.8.3", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "accountsservice-lang", rpm: "accountsservice-lang~0.6.42~16.8.3", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaccountsservice0", rpm: "libaccountsservice0~0.6.42~16.8.3", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libaccountsservice0-debuginfo", rpm: "libaccountsservice0-debuginfo~0.6.42~16.8.3", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-AccountsService-1_0", rpm: "typelib-1_0-AccountsService-1_0~0.6.42~16.8.3", rls: "SLES12.0SP5" ) )){
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

