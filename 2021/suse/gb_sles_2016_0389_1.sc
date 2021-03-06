if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0389.1" );
	script_cve_id( "CVE-2015-5288" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0389-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0389-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160389-1/" );
	script_xref( name: "URL", value: "http://www.postgresql.org/docs/9.1/static/release-9-1-19.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql91' package(s) announced via the SUSE-SU-2016:0389-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of postgresql91 to 9.1.19 fixes the following issues:
* CVE-2015-5288: crypt() (pgCrypto extension) couldi potentially be
 exploited to read a few additional bytes of memory (bsc#949669)
Also contains all changes and bugfixes in the upstream 9.1.19 release:
[link moved to references]" );
	script_tag( name: "affected", value: "'postgresql91' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for VMWare 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3, SUSE Manager 2.1, SUSE Studio Onsite 1.3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql91", rpm: "postgresql91~9.1.19~0.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql91-contrib", rpm: "postgresql91-contrib~9.1.19~0.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql91-docs", rpm: "postgresql91-docs~9.1.19~0.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql91-server", rpm: "postgresql91-server~9.1.19~0.5.1", rls: "SLES11.0SP3" ) )){
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

