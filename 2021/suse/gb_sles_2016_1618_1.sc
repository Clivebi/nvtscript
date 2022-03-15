if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.1618.1" );
	script_cve_id( "CVE-2015-4000" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:1618-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:1618-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20161618-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql' package(s) announced via the SUSE-SU-2016:1618-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mysql fixes the following issues:
- bsc#959724: fix incorrect usage of sprintf/strcpy that caused possible
 buffer overflow issues at various places On SUSE Linux Enterprise 11 SP4 this fix was not yet shipped:
- Increase the key length (to 2048 bits) used in vio/viosslfactories.c for
 creating Diffie-Hellman keys (Logjam Attack) [bnc#934789] [CVE-2015-4000]" );
	script_tag( name: "affected", value: "'mysql' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient15-32bit", rpm: "libmysqlclient15-32bit~5.0.96~0.8.10.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient15", rpm: "libmysqlclient15~5.0.96~0.8.10.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient15-x86", rpm: "libmysqlclient15-x86~5.0.96~0.8.10.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient_r15", rpm: "libmysqlclient_r15~5.0.96~0.8.10.3", rls: "SLES11.0SP4" ) )){
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

